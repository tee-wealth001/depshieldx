// Runs inside the Docker sandbox container for npm deep-mode installs -- the
// npm counterpart to sandbox_wrapper.py. Written in Node (not Python): the
// container image is node:20, which has no guaranteed Python interpreter,
// unlike the PyPI sandbox's python:3.11 image.
//
// Stage 2 (this file, initial version): installs every pre-downloaded,
// already-integrity-verified tarball (see ecosystems/npm.py's fetch_artifact
// -- SRI sha512/sha256/sha1 check against the registry's own digest, done on
// the host *before* this script runs) directly by local file path, entirely
// without network access inside the container (--network none is set by
// sandbox.py's docker run invocation, same isolation posture as the PyPI
// sandbox).
//
// This installs from explicit tarball paths rather than a synthetic
// name@version package.json seeded via `npm cache add` + `npm install
// --offline`, which was tried first and reproducibly failed: `npm cache add`
// only seeds the tarball *fetch* response, not the registry packument
// (metadata) response `npm install --offline` still needs to resolve a
// version range against, so it fails with ENOTCACHED even once the tarball
// itself is cached. Passing every resolved (direct + transitive) package's
// tarball path explicitly sidesteps resolution entirely: npm reads each
// package's name/version straight from its own package.json inside the
// tarball, and satisfies nested "dependencies" from the other tarballs
// already present in the same flat install -- verified directly against a
// real two-tarball (dependent + dependency) offline install in a real
// container, never touching the network.
//
// No behavioral tracing here yet -- this only proves the install itself
// completes correctly offline, including running install lifecycle scripts.
// Stage 3 adds real syscall-level tracing (strace wrapped around the same
// `npm install` call, not a rewrite of this file's install logic).
//
// Prints the same DEPSHIELDX_SANDBOX_REPORT=<json> line sandbox.py's
// _extract_report() already expects, with the same key shape cli/output.py's
// summary formatter reads (write_count, syscall_counts,
// allowed_subprocesses, imported_modules, import_failures, skipped_imports,
// blocked_events, verdicts) -- all empty/zero until Stage 3 populates them
// for real, so downstream report rendering works unchanged for either
// ecosystem.

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const REPORT_PREFIX = "DEPSHIELDX_SANDBOX_REPORT=";

function main() {
  if (process.argv.length < 3) {
    process.stderr.write("usage: sandbox_wrapper_npm.js <packages_dir>\n");
    return 2;
  }

  const packagesDir = process.argv[2];
  const npmPath = "npm";

  const installDir = "/tmp/depshieldx-npm-install";
  fs.mkdirSync(installDir, { recursive: true });
  fs.writeFileSync(
    path.join(installDir, "package.json"),
    JSON.stringify({ name: "depshieldx-sandbox", version: "0.0.0", private: true })
  );

  const tarballPaths = fs
    .readdirSync(packagesDir)
    .filter((name) => name.endsWith(".tgz"))
    .sort()
    .map((name) => path.join(packagesDir, name));

  const result = spawnSync(
    npmPath,
    ["install", "--offline", "--no-audit", "--no-fund", "--no-save", ...tarballPaths],
    { cwd: installDir, encoding: "utf8" },
  );
  const installExitCode = result.status === null ? 1 : result.status;
  const suspicious = installExitCode !== 0;

  const report = {
    install_exit_code: installExitCode,
    suspicious,
    installed_tarballs: tarballPaths.map((tarballPath) => path.basename(tarballPath)),
    install_stdout_tail: suspicious ? (result.stdout || "").slice(-2000) : "",
    install_stderr_tail: suspicious ? (result.stderr || "").slice(-2000) : "",
    write_count: 0,
    write_buckets: {},
    write_samples: [],
    syscall_counts: { filesystem_mutation: 0, process_exec: 0, network: 0 },
    syscall_samples: [],
    allowed_subprocesses: [],
    imported_modules: [],
    import_failures: [],
    risky_import_failures: [],
    environmental_import_failures: [],
    skipped_imports: [],
    blocked_events: [],
    events: [],
    verdicts: [],
  };
  process.stdout.write(REPORT_PREFIX + JSON.stringify(report) + "\n");
  return suspicious ? 1 : 0;
}

process.exit(main());
