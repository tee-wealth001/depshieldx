import re
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List


MAX_SCAN_BYTES = 512_000
MAX_BINARY_SCAN_BYTES = 1_048_576
# .tgz/.tar archives are already handled generically below (npm tarballs use
# the same tar+gzip format sdists do; .crate files -- crates.io's own
# artifact format -- are confirmed to be plain gzipped tarballs too, same
# handling) -- these two sets are what actually gate per-file scanning, and
# were PyPI-only until npm deep mode needed them too: .js/.mjs/.cjs/.ts/.json
# cover npm package source and manifests, package.json is npm's
# "install_only" analogue to setup.py, .rs covers Rust source (build.rs in
# particular), and build.rs is cargo's own "install_only" analogue -- a
# script name every crate agrees on, always executed automatically at build
# time before the crate itself compiles, unlike arbitrary .rs source files a
# user would have to explicitly depend on. ".go" covers Go module source --
# Go module zips are plain zip archives (confirmed directly), so the
# existing .zip branch below already opens and scans them, no new archive-
# format code needed. Deliberately no Go entry in INSTALL_SCRIPT_NAMES:
# unlike setup.py/build.rs, Go has no canonical, always-executed
# build-time script -- init() functions and //go:generate directives only
# run during a real `go build`/`go generate`, not during `go mod download`
# alone, and neither is a single agreed-upon filename the way build.rs is.
# Maven jars need no TEXT_EXTENSIONS entry -- they contain compiled
# .class bytecode, not text source, and real jars are plain zip archives
# (confirmed directly), so only the top-level archive-suffix check below
# needs ".jar" added, no new extraction code. Deliberately no Maven entry
# in INSTALL_SCRIPT_NAMES either: like Go, Maven has no canonical,
# always-executed build-time script that runs during plain dependency
# resolution -- annotation processors only run during a real `mvn
# compile`, not `dependency:resolve` alone.
TEXT_EXTENSIONS = {".py", ".toml", ".cfg", ".ini", ".js", ".mjs", ".cjs", ".ts", ".json", ".rs", ".go"}
INSTALL_SCRIPT_NAMES = {"setup.py", "pyproject.toml", "setup.cfg", "package.json", "build.rs"}
NATIVE_BINARY_SUFFIXES = (".so", ".dylib", ".pyd", ".dll")
ASCII_STRING_PATTERN = re.compile(rb"[\x20-\x7e]{6,}")
URL_PATTERN = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,}")
LONG_BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{160,}={0,2})")
LONG_HEX_PATTERN = re.compile(r"[A-Fa-f0-9]{192,}")
SHELL_SNIPPET_PATTERNS = (
    "curl ",
    "wget ",
    "powershell -enc",
    "bash -c",
    "sh -c",
    "cmd.exe /c",
    "cmd /c",
)
NETWORK_INDICATORS = (
    "socket",
    "connect",
    "getaddrinfo",
    "curl_easy_perform",
    "curl_easy_setopt",
    "internetopen",
    "httpopenrequest",
    "winhttp",
    "wsastartup",
)
STRONG_NETWORK_INDICATORS = (
    "curl_easy_perform",
    "curl_easy_setopt",
    "internetopen",
    "httpopenrequest",
    "winhttp",
)
EXEC_INDICATORS = (
    "/bin/sh",
    "/bin/bash",
    "cmd.exe",
    "powershell",
    "createprocess",
    "shellexecute",
    "posix_spawn",
    "execve",
    "popen",
)
STRONG_EXEC_INDICATORS = (
    "/bin/sh",
    "/bin/bash",
    "cmd.exe",
    "powershell",
    "createprocess",
    "shellexecute",
)

# Binaries that commonly have network/exec symbols due to dependencies
# (e.g., linking against OpenSSL, libcurl, or standard libc)
EXPECTED_COMPILED_EXTENSIONS = {
    "uuid_utils",
    "orjson",
    "ormsgpack",
    "pydantic_core",
    "cryptography",
    "bcrypt",
    "cffi",
}
LOADER_INDICATORS = (
    "loadlibrary",
    "dlopen",
    "dlsym",
    "virtualalloc",
    "virtualprotect",
    "memfd_create",
)
MAGIC_SIGNATURES = (
    ("zip archive", b"PK\x03\x04"),
    ("gzip stream", b"\x1f\x8b\x08"),
    ("ELF executable", b"\x7fELF"),
    ("Mach-O binary", b"\xfe\xed\xfa\xce"),
    ("Mach-O binary", b"\xce\xfa\xed\xfe"),
    ("Mach-O binary", b"\xfe\xed\xfa\xcf"),
    ("Mach-O binary", b"\xcf\xfa\xed\xfe"),
)
EXECUTABLE_MAGIC_SIGNATURES = tuple(
    (label, signature)
    for label, signature in MAGIC_SIGNATURES
    if "executable" in label or "Mach-O" in label
)
SENSITIVE_ENV_ACCESS_PATTERN = re.compile(
    r"""
    (
        os\.environ(?:\.get)?\(
            \s*["']
            (AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|PYPI_TOKEN|NPM_TOKEN|API_KEY|PRIVATE_KEY|BEARER_TOKEN)
            ["']
        |
        os\.environ\[
            \s*["']
            (AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|PYPI_TOKEN|NPM_TOKEN|API_KEY|PRIVATE_KEY|BEARER_TOKEN)
            ["']
            \s*
        \]
        |
        getenv\(
            \s*["']
            (AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|PYPI_TOKEN|NPM_TOKEN|API_KEY|PRIVATE_KEY|BEARER_TOKEN)
            ["']
        \s*\)
        |
        env::var\(
            \s*["']
            (AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|PYPI_TOKEN|NPM_TOKEN|API_KEY|PRIVATE_KEY|BEARER_TOKEN)
            ["']
        \s*\)
        |
        process\.env(?:\.|\[["']?)
            (AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|PYPI_TOKEN|NPM_TOKEN|API_KEY|PRIVATE_KEY|BEARER_TOKEN)
            ["']?\]?
    )
    """,
    re.VERBOSE,
)
PAYLOAD_CHAIN_PATTERN = re.compile(
    r"\b(base64\.b64decode|marshal\.loads|zlib\.decompress|Buffer\.from\s*\([^)]*base64|atob)\b.*"
    r"\b(exec|eval|compile|Function)\s*\(",
    re.DOTALL,
)
PATTERN_RULES = (
    {
        "code": "install_exec_eval",
        "severity": "high",
        "pattern": re.compile(r"\b(exec|eval|compile)\s*\("),
        "install_only": True,
        "message": "Install script uses dynamic code execution.",
    },
    {
        "code": "install_network_access",
        "severity": "high",
        "pattern": re.compile(r"\b(requests\.(get|post)|urllib\.request|socket\.|httpx\.)"),
        "install_only": True,
        "message": "Install script appears to perform network access.",
    },
    {
        "code": "install_subprocess",
        "severity": "high",
        "pattern": re.compile(r"\b(subprocess\.|os\.system\s*\()"),
        "install_only": True,
        "message": "Install script launches shell or subprocess commands.",
    },
    {
        "code": "install_exec_eval_js",
        "severity": "high",
        "pattern": re.compile(r"\b(eval|new Function)\s*\("),
        "install_only": True,
        "message": "Install script uses dynamic code execution.",
    },
    {
        "code": "install_network_access_js",
        "severity": "high",
        "pattern": re.compile(r"\brequire\s*\(\s*['\"](https?|net|dgram)['\"]\s*\)|\bfetch\s*\(|\baxios\."),
        "install_only": True,
        "message": "Install script appears to perform network access.",
    },
    {
        "code": "install_subprocess_js",
        "severity": "high",
        "pattern": re.compile(r"require\s*\(\s*['\"]child_process['\"]\s*\)|\b(exec|execSync|spawn|spawnSync)\s*\("),
        "install_only": True,
        "message": "Install script launches shell or subprocess commands.",
    },
    {
        # No Rust equivalent of "install_exec_eval" -- Rust is compiled, not
        # dynamically interpreted, so there's no eval()/exec() analogue for
        # build.rs to abuse the way Python/JS install scripts can.
        "code": "install_network_access_rust",
        "severity": "high",
        "pattern": re.compile(r"\b(TcpStream::connect|reqwest::|ureq::|curl::easy::)"),
        "install_only": True,
        "message": "Install script appears to perform network access.",
    },
    {
        # Narrower than the Python/JS subprocess rules: `Command::new(...)`
        # by itself is far too common in legitimate build.rs scripts to
        # flag generically -- confirmed directly against the real, benign
        # serde build.rs, which shells out to `Command::new(rustc).arg(
        # "--version")` to feature-gate on the compiler version (the exact
        # same widely-used idiom sandbox_wrapper.py's own
        # ALLOWED_SUBPROCESS_PREFIXES already allowlists as benign for
        # PyPI/npm). Only flag when the command target itself is a shell,
        # network-fetch tool, or another scripting interpreter -- the same
        # class of literal command names SHELL_SNIPPET_PATTERNS already
        # treats as suspicious for compiled binaries above.
        "code": "install_subprocess_rust",
        "severity": "high",
        "pattern": re.compile(
            r'Command::new\s*\(\s*"(?:/bin/)?(?:sh|bash|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?|curl|wget|nc|ncat|python[23]?|perl|ruby)"'
        ),
        "install_only": True,
        "message": "Install script launches a shell or network-fetch subprocess.",
    },
    {
        "code": "payload_obfuscation",
        "severity": "medium",
        "pattern": PAYLOAD_CHAIN_PATTERN,
        "install_only": False,
        "message": "Package chains payload deobfuscation with dynamic code execution.",
    },
    {
        "code": "sensitive_env_access",
        "severity": "medium",
        "pattern": SENSITIVE_ENV_ACCESS_PATTERN,
        "install_only": False,
        "message": "Package directly accesses high-risk credential environment variables.",
    },
)


@dataclass
class StaticFinding:
    severity: str
    code: str
    artifact: str
    file: str
    message: str

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "code": self.code,
            "artifact": self.artifact,
            "file": self.file,
            "message": self.message,
        }


def _is_text_candidate(member: str) -> bool:
    path = Path(member)
    return path.suffix.lower() in TEXT_EXTENSIONS or path.name in INSTALL_SCRIPT_NAMES


def _is_native_binary(member: str) -> bool:
    lowered = member.lower()
    return any(lowered.endswith(suffix) for suffix in NATIVE_BINARY_SUFFIXES)


def _candidate_members(artifact_name: str, members: Iterable[str]) -> List[str]:
    candidates = []
    for member in members:
        if _is_text_candidate(member) or _is_native_binary(member):
            candidates.append(member)
    return candidates


def _scan_text(artifact_name: str, member_name: str, text: str) -> List[StaticFinding]:
    findings = []
    basename = Path(member_name).name
    install_file = basename in INSTALL_SCRIPT_NAMES

    for rule in PATTERN_RULES:
        if rule["install_only"] and not install_file:
            continue
        if not rule["pattern"].search(text):
            continue
        findings.append(
            StaticFinding(
                severity=rule["severity"],
                code=rule["code"],
                artifact=artifact_name,
                file=member_name,
                message=rule["message"],
            )
        )
    return findings


def _read_binary_file(path: Path) -> bytes:
    with path.open("rb") as fh:
        return fh.read(MAX_BINARY_SCAN_BYTES)


def _read_zip_member(archive: zipfile.ZipFile, member_name: str) -> str:
    with archive.open(member_name) as member_file:
        return member_file.read(MAX_SCAN_BYTES).decode("utf-8", errors="ignore")


def _read_zip_binary_member(archive: zipfile.ZipFile, member_name: str) -> bytes:
    with archive.open(member_name) as member_file:
        return member_file.read(MAX_BINARY_SCAN_BYTES)


def _read_tar_member(archive: tarfile.TarFile, member_name: str) -> str:
    extracted = archive.extractfile(member_name)
    if extracted is None:
        return ""
    try:
        return extracted.read(MAX_SCAN_BYTES).decode("utf-8", errors="ignore")
    finally:
        extracted.close()


def _read_tar_binary_member(archive: tarfile.TarFile, member_name: str) -> bytes:
    extracted = archive.extractfile(member_name)
    if extracted is None:
        return b""
    try:
        return extracted.read(MAX_BINARY_SCAN_BYTES)
    finally:
        extracted.close()


def _binary_kind(data: bytes) -> str | None:
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data.startswith((b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")):
        return "Mach-O"
    if data.startswith(b"MZ"):
        pe_header_offset = int.from_bytes(data[0x3C:0x40], "little", signed=False) if len(data) >= 0x40 else 0
        if 0 < pe_header_offset < len(data) - 4 and data[pe_header_offset:pe_header_offset + 4] == b"PE\x00\x00":
            return "PE"
        return "MZ"
    return None


def _extract_ascii_strings(data: bytes) -> list[str]:
    return [match.group().decode("latin-1", errors="ignore") for match in ASCII_STRING_PATTERN.finditer(data)]


def _contains_indicator(strings: list[str], indicators: Iterable[str]) -> bool:
    lowered = [value.lower() for value in strings]
    return any(indicator in value for value in lowered for indicator in indicators)


def _urls_from_strings(strings: list[str]) -> list[str]:
    urls = set()
    for value in strings:
        urls.update(match.group(0) for match in URL_PATTERN.finditer(value))
    return sorted(urls)


def _has_encoded_blob(strings: list[str]) -> bool:
    for value in strings:
        if LONG_BASE64_PATTERN.search(value) or LONG_HEX_PATTERN.search(value):
            return True
    return False


def _find_embedded_payload(data: bytes) -> str | None:
    kind = _binary_kind(data)
    signatures = EXECUTABLE_MAGIC_SIGNATURES if kind == "PE" else MAGIC_SIGNATURES
    for label, signature in signatures:
        offset = data.find(signature, 1)
        if offset > 0:
            return f"{label} at offset {offset}"

    offset = data.find(b"MZ", 1)
    while offset > 0:
        pe_header_end = min(offset + 1024, len(data) - 4)
        if pe_header_end > offset and data.find(b"PE\x00\x00", offset, pe_header_end) != -1:
            return f"PE executable at offset {offset}"
        offset = data.find(b"MZ", offset + 1)

    if kind == "PE":
        return None
    return None


def _is_expected_compiled_extension(artifact_name: str) -> bool:
    """Check if this is a known compiled extension that commonly has network/exec symbols."""
    basename = Path(artifact_name).stem.lower()
    for expected_pkg in EXPECTED_COMPILED_EXTENSIONS:
        if expected_pkg in basename:
            return True
    return False


def _is_benign_url(url: str) -> bool:
    """Filter out URLs that are clearly benign (documentation, issue trackers, source repos)."""
    benign_domains = {
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "pypi.org",
        "python.org",
        "docs.python.org",
        "readthedocs.io",
    }
    url_lower = url.lower()
    return any(domain in url_lower for domain in benign_domains)


def _scan_binary(artifact_name: str, member_name: str, data: bytes) -> List[StaticFinding]:
    findings = []
    strings = _extract_ascii_strings(data)
    all_urls = _urls_from_strings(strings)
    # Filter out benign URLs (documentation, source repos, etc.)
    urls = [u for u in all_urls if not _is_benign_url(u)]
    has_network = _contains_indicator(strings, NETWORK_INDICATORS)
    has_strong_network = _contains_indicator(strings, STRONG_NETWORK_INDICATORS)
    has_exec = _contains_indicator(strings, EXEC_INDICATORS)
    has_strong_exec = _contains_indicator(strings, STRONG_EXEC_INDICATORS)
    has_loader = _contains_indicator(strings, LOADER_INDICATORS)
    has_encoded_blob = _has_encoded_blob(strings)
    has_shell_snippet = _contains_indicator(strings, SHELL_SNIPPET_PATTERNS)
    embedded_payload = _find_embedded_payload(data)
    binary_kind = _binary_kind(data) or "native"
    is_known_extension = _is_expected_compiled_extension(artifact_name)

    embedded_payload_is_suspicious = bool(
        embedded_payload
        and (
            binary_kind != "PE"
            or urls
            or has_loader
            or has_encoded_blob
            or has_shell_snippet
            or has_exec
        )
    )

    # Embedded payloads are suspicious on their own for non-PE native binaries.
    # For PE extensions, require some corroborating process-launch or loader signal
    # to avoid flagging incidental bytes in otherwise normal modules.
    if embedded_payload_is_suspicious:
        findings.append(
            StaticFinding(
                severity="high",
                code="binary_embedded_payload",
                artifact=artifact_name,
                file=member_name,
                message=f"{binary_kind} binary contains an embedded {embedded_payload}, which may indicate a hidden payload.",
            )
        )

    # Only flag HIGH severity if there's strong evidence of malicious intent
    # (actual non-benign URLs or shell snippets + exec), not just symbol presence
    combo_is_genuinely_suspicious = bool(
        urls  # malicious URLs (after filtering benign ones)
        or has_shell_snippet
        or (has_loader and has_encoded_blob)
        or (has_strong_network and has_strong_exec)
    )

    if has_network and has_exec and combo_is_genuinely_suspicious and not is_known_extension:
        findings.append(
            StaticFinding(
                severity="high",
                code="binary_network_exec_combo",
                artifact=artifact_name,
                file=member_name,
                message="Native binary exposes both network and process-launch indicators with suspicious corroboration.",
            )
        )
    elif has_network and has_exec and not is_known_extension:
        # Only report MEDIUM if NOT a known compiled extension
        findings.append(
            StaticFinding(
                severity="medium",
                code="binary_network_exec_symbols",
                artifact=artifact_name,
                file=member_name,
                message="Native binary exposes both network and process-launch symbols, but lacks suspicious corroboration.",
            )
        )

    if urls:
        findings.append(
            StaticFinding(
                severity="medium",
                code="binary_embedded_urls",
                artifact=artifact_name,
                file=member_name,
                message="Native binary embeds suspicious outbound URLs or remote endpoints.",
            )
        )

    if has_loader and has_encoded_blob and not is_known_extension:
        findings.append(
            StaticFinding(
                severity="medium",
                code="binary_encoded_loader",
                artifact=artifact_name,
                file=member_name,
                message="Native binary combines dynamic loader APIs with a long encoded blob.",
            )
        )

    if has_shell_snippet and not (has_network and has_exec) and not is_known_extension:
        findings.append(
            StaticFinding(
                severity="medium",
                code="binary_shell_fragments",
                artifact=artifact_name,
                file=member_name,
                message="Native binary embeds shell command fragments.",
            )
        )

    return findings


def analyze_artifact(artifact_path: Path) -> List[StaticFinding]:
    findings: List[StaticFinding] = []
    suffixes = artifact_path.suffixes

    if _is_native_binary(artifact_path.name):
        data = _read_binary_file(artifact_path)
        findings.extend(_scan_binary(artifact_path.name, artifact_path.name, data))
        return findings

    if artifact_path.suffix in (".whl", ".zip", ".jar"):
        with zipfile.ZipFile(artifact_path) as archive:
            for member_name in _candidate_members(artifact_path.name, archive.namelist()):
                if _is_native_binary(member_name):
                    data = _read_zip_binary_member(archive, member_name)
                    findings.extend(_scan_binary(artifact_path.name, member_name, data))
                else:
                    text = _read_zip_member(archive, member_name)
                    findings.extend(_scan_text(artifact_path.name, member_name, text))
        return findings

    if suffixes[-2:] == [".tar", ".gz"] or artifact_path.suffix in {".tgz", ".tar", ".crate"}:
        mode = "r:gz" if artifact_path.suffix != ".tar" else "r:"
        with tarfile.open(artifact_path, mode) as archive:
            member_names = [member.name for member in archive.getmembers() if member.isfile()]
            for member_name in _candidate_members(artifact_path.name, member_names):
                if _is_native_binary(member_name):
                    data = _read_tar_binary_member(archive, member_name)
                    findings.extend(_scan_binary(artifact_path.name, member_name, data))
                else:
                    text = _read_tar_member(archive, member_name)
                    findings.extend(_scan_text(artifact_path.name, member_name, text))
        return findings

    return findings


def analyze_artifacts(directory: str) -> dict:
    findings: List[StaticFinding] = []
    artifacts = sorted(path for path in Path(directory).iterdir() if path.is_file())
    for artifact in artifacts:
        findings.extend(analyze_artifact(artifact))

    serialized = [finding.as_dict() for finding in findings]
    high = [item for item in serialized if item["severity"] == "high"]
    medium = [item for item in serialized if item["severity"] == "medium"]
    blocked = bool(high)
    return {
        "artifacts_scanned": [artifact.name for artifact in artifacts],
        "finding_count": len(serialized),
        "high_count": len(high),
        "medium_count": len(medium),
        "blocked": blocked,
        "findings": serialized,
    }
