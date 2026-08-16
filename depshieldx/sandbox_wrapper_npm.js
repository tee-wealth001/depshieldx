// Runs inside the Docker sandbox container for npm deep-mode installs -- the
// npm counterpart to sandbox_wrapper.py. Written in Node (not Python): the
// container image is a custom node:20 + strace build (see
// depshieldx/docker/npm_sandbox.Dockerfile), which has no guaranteed Python
// interpreter, unlike the PyPI sandbox's python:3.11 image.
//
// Stage 2 installed every pre-downloaded, already-integrity-verified
// tarball (see ecosystems/npm.py's fetch_artifact) directly by local file
// path, entirely offline. Stage 3 (this file) adds real behavioral tracing
// on top of that same install: there is no Node equivalent of Python's
// sys.addaudithook (the mechanism sandbox_wrapper.py's in-process
// monkeypatching relies on), so this wraps the whole `npm install` process
// tree in `strace -f`, which observes every traced syscall any child
// process makes -- including install lifecycle scripts (preinstall/
// install/postinstall), which is exactly where a malicious package would
// act. Unlike sandbox_wrapper.py's guards, this doesn't *block* individual
// syscalls in real time (ptrace-based interception/denial is a much bigger
// undertaking than observation) -- filesystem isolation and network denial
// are already enforced by the container itself (--read-only rootfs,
// --network none), so a malicious script's writes/connects fail at the OS
// level regardless; strace's job is to notice that it tried, and report it
// the same way sandbox_wrapper.py reports a *blocked* attempt.
//
// Verified directly against a real container under the exact sandbox
// posture (--cap-drop ALL plus --cap-add SYS_PTRACE, non-root user,
// --read-only rootfs, --security-opt no-new-privileges): strace traces a
// child process it spawns itself without issue, and a connect() to a real
// AF_INET address shows up in the trace as ENETUNREACH -- proof the
// container's --network none is doing its job *and* that the attempt is
// still visible as evidence.
//
// Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
// _extract_report() already expects, with the same key shape cli/output.py's
// summary formatter reads (write_count, syscall_counts,
// allowed_subprocesses, imported_modules, import_failures, skipped_imports,
// blocked_events, verdicts).

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT=";
const STRACE_LOG_PATH = "/tmp/depshieldx-strace.log";
const MAX_SAMPLES = 12;
const MAX_SUBPROCESSES = 8;
const MAX_WRITE_SAMPLES = 8;

const WRITE_OPEN_FLAGS = ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"];
const MUTATION_SYSCALLS = new Set([
  "unlink",
  "unlinkat",
  "rmdir",
  "mkdir",
  "mkdirat",
  "rename",
  "renameat",
  "renameat2",
  "symlink",
  "symlinkat",
  "chmod",
  "fchmodat",
]);
const OPEN_SYSCALLS = new Set(["open", "openat"]);
const EXEC_SYSCALLS = new Set(["execve", "execveat"]);

// strace line shape (with -f, multi-process): "<pid>  <syscall>(<args>) = <retval> [errno text]"
// e.g. `21    connect(18, {sa_family=AF_INET, ...}, 16) = -1 ENETUNREACH (Network is unreachable)`
const SYSCALL_LINE = /^\s*(\d+)\s+(\w+)\((.*)\)\s*=\s*(-?\d+|0x[0-9a-f]+)(.*)$/;

function extractFirstQuotedString(text) {
  const match = text.match(/"((?:[^"\\]|\\.)*)"/);
  return match ? match[1] : null;
}

function extractArgv(text) {
  const match = text.match(/\[(.*?)\]/);
  if (!match) return [];
  const argv = [];
  const stringPattern = /"((?:[^"\\]|\\.)*)"/g;
  let item;
  while ((item = stringPattern.exec(match[1])) !== null) {
    argv.push(item[1]);
  }
  return argv;
}

function classifyWritePath(rawPath) {
  const normalized = rawPath.replace(/\\/g, "/");
  if (normalized.endsWith(".node")) return "native_extensions";
  if (normalized.includes("/node_modules/.bin/")) return "entrypoint_scripts";
  if (normalized.endsWith("package.json") || normalized.endsWith("package-lock.json")) {
    return "metadata_files";
  }
  if (normalized.includes("/node_modules/")) return "package_files";
  return "other";
}

function isRemoteConnect(argsText) {
  return /sa_family=AF_INET6?\b/.test(argsText);
}

function runStracedInstall(installDir, tarballPaths) {
  const straceArgs = [
    "-f",
    "-s",
    "200",
    "-e",
    "trace=file,process,network",
    "-o",
    STRACE_LOG_PATH,
    "npm",
    "install",
    "--offline",
    "--no-audit",
    "--no-fund",
    "--no-save",
    // Without a persisted npm config/state (a fresh HOME=/tmp every run),
    // npm's own update-notifier unconditionally makes a real DNS lookup +
    // connect() attempt on every invocation -- reproduced directly, and
    // without this flag it's indistinguishable from a package doing the
    // same thing, poisoning every clean install with a false
    // network_attempt_blocked verdict.
    "--no-update-notifier",
    ...tarballPaths,
  ];
  return spawnSync("strace", straceArgs, { cwd: installDir, encoding: "utf8" });
}

function parseStraceLog(logPath) {
  const evidence = {
    writeCount: 0,
    writeSamples: [],
    writeBuckets: { package_files: 0, metadata_files: 0, entrypoint_scripts: 0, native_extensions: 0, other: 0 },
    syscallCounts: { filesystem_mutation: 0, process_exec: 0, network: 0 },
    syscallSamples: [],
    subprocesses: [],
    blockedEvents: [],
  };

  let logText;
  try {
    logText = fs.readFileSync(logPath, "utf8");
  } catch {
    return evidence;
  }

  const seenSubprocesses = new Set();

  for (const line of logText.split("\n")) {
    const match = line.match(SYSCALL_LINE);
    if (!match) continue;
    const [, , syscall, argsText, retval] = match;

    if (OPEN_SYSCALLS.has(syscall)) {
      const isWrite = WRITE_OPEN_FLAGS.some((flag) => argsText.includes(flag));
      if (!isWrite) continue;
      const filePath = extractFirstQuotedString(argsText);
      evidence.syscallCounts.filesystem_mutation += 1;
      if (evidence.syscallSamples.length < MAX_SAMPLES) {
        evidence.syscallSamples.push({ category: "syscall:filesystem_mutation", detail: { call: syscall, path: filePath } });
      }
      if (filePath) {
        evidence.writeCount += 1;
        if (evidence.writeSamples.length < MAX_WRITE_SAMPLES && !evidence.writeSamples.includes(filePath)) {
          evidence.writeSamples.push(filePath);
        }
        evidence.writeBuckets[classifyWritePath(filePath)] += 1;
      }
      continue;
    }

    if (MUTATION_SYSCALLS.has(syscall)) {
      const filePath = extractFirstQuotedString(argsText);
      evidence.syscallCounts.filesystem_mutation += 1;
      if (evidence.syscallSamples.length < MAX_SAMPLES) {
        evidence.syscallSamples.push({ category: "syscall:filesystem_mutation", detail: { call: syscall, path: filePath } });
      }
      continue;
    }

    if (EXEC_SYSCALLS.has(syscall)) {
      evidence.syscallCounts.process_exec += 1;
      const argv = extractArgv(argsText);
      const command = argv.length ? argv : [extractFirstQuotedString(argsText)].filter(Boolean);
      if (evidence.syscallSamples.length < MAX_SAMPLES) {
        evidence.syscallSamples.push({ category: "syscall:process_exec", detail: { call: syscall, command } });
      }
      const key = JSON.stringify(command);
      if (command.length && !seenSubprocesses.has(key) && evidence.subprocesses.length < MAX_SUBPROCESSES) {
        seenSubprocesses.add(key);
        evidence.subprocesses.push(command);
      }
      continue;
    }

    if (syscall === "connect" && isRemoteConnect(argsText)) {
      evidence.syscallCounts.network += 1;
      const detail = { call: syscall, args: argsText.trim(), retval };
      if (evidence.syscallSamples.length < MAX_SAMPLES) {
        evidence.syscallSamples.push({ category: "syscall:network", detail });
      }
      evidence.blockedEvents.push({ category: "network_denied", detail });
    }
  }

  return evidence;
}

function buildVerdicts(evidence, installExitCode) {
  const verdicts = [];

  if (evidence.blockedEvents.length > 0) {
    verdicts.push({
      severity: "high",
      code: "network_attempt_blocked",
      message: "Package attempted network access during sandboxed install.",
    });
  }

  if (installExitCode !== 0 && evidence.blockedEvents.length === 0) {
    verdicts.push({
      severity: "medium",
      code: "install_failed",
      message: "The sandboxed install failed without triggering an explicit policy block.",
    });
  }

  if (evidence.writeBuckets.native_extensions > 0) {
    verdicts.push({
      severity: "info",
      code: "native_extensions_present",
      message: "The package install wrote native extension binaries inside the target environment.",
    });
  }

  if (evidence.writeBuckets.entrypoint_scripts > 0) {
    verdicts.push({
      severity: "info",
      code: "entrypoint_scripts_created",
      message: "The package install created executable entrypoint scripts.",
    });
  }

  if (evidence.syscallCounts.process_exec > 0) {
    verdicts.push({
      severity: "info",
      code: "subprocess_execs_traced",
      message: "The package install spawned subprocesses (e.g. lifecycle scripts) during sandboxed install.",
    });
  }

  if (evidence.syscallCounts.filesystem_mutation > 0) {
    verdicts.push({
      severity: "info",
      code: "filesystem_mutations_traced",
      message: "Low-level filesystem mutation calls were traced during sandboxed install.",
    });
  }

  return verdicts;
}

function main() {
  if (process.argv.length < 3) {
    process.stderr.write("usage: sandbox_wrapper_npm.js <packages_dir>\n");
    return 2;
  }

  const packagesDir = process.argv[2];

  const installDir = "/tmp/depshieldx-npm-install";
  fs.mkdirSync(installDir, { recursive: true });
  fs.writeFileSync(
    path.join(installDir, "package.json"),
    JSON.stringify({ name: "depshieldx-sandbox", version: "0.0.0", private: true }),
  );

  const tarballPaths = fs
    .readdirSync(packagesDir)
    .filter((name) => name.endsWith(".tgz"))
    .sort()
    .map((name) => path.join(packagesDir, name));

  const result = runStracedInstall(installDir, tarballPaths);
  const installExitCode = result.status === null ? 1 : result.status;

  const evidence = parseStraceLog(STRACE_LOG_PATH);
  const verdicts = buildVerdicts(evidence, installExitCode);
  const suspicious = installExitCode !== 0 || verdicts.some((verdict) => verdict.severity === "high");

  const report = {
    install_exit_code: installExitCode,
    suspicious,
    installed_tarballs: tarballPaths.map((tarballPath) => path.basename(tarballPath)),
    install_stdout_tail: installExitCode !== 0 ? (result.stdout || "").slice(-2000) : "",
    install_stderr_tail: installExitCode !== 0 ? (result.stderr || "").slice(-2000) : "",
    write_count: evidence.writeCount,
    write_buckets: evidence.writeBuckets,
    write_samples: evidence.writeSamples,
    syscall_counts: evidence.syscallCounts,
    syscall_samples: evidence.syscallSamples,
    allowed_subprocesses: evidence.subprocesses,
    imported_modules: [],
    import_failures: [],
    risky_import_failures: [],
    environmental_import_failures: [],
    skipped_imports: [],
    blocked_events: evidence.blockedEvents,
    events: [],
    verdicts,
  };
  process.stdout.write(REPORT_PREFIX + JSON.stringify(report) + "\n");
  return suspicious ? 1 : 0;
}

process.exit(main());
