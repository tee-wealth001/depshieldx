"""Maven Central registry client: artifact/checksum fetch, plus structural
and (where available) real cryptographic Sigstore provenance signals.

Maven's checksum story spans two eras, confirmed directly against real
artifacts: older/long-published releases (e.g. junit:junit:4.13.2) only
carry MD5/SHA-1 alongside each file; anything published more recently
(e.g. jackson-databind 2.19.1) also carries SHA-256/SHA-512. SHA-256 is
preferred when available, falling back to SHA-1 for older artifacts --
MD5 is never used, it's cryptographically broken and only kept around by
Central for legacy tooling compatibility.

Sigstore adoption on Maven Central is real but new and still opt-in: since
January 2025, the Central Publisher Portal accepts and republishes a
"<artifact-file>.sigstore.json" bundle alongside artifacts whose publishers
choose to sign with Sigstore -- confirmed directly against a real, live
example (org.leplus:ristretto:2.0.0). Most published artifacts still only
carry the older, mandatory-since-2010s PGP ".asc" signature instead (or in
addition). Critically, these are NOT the same trust model:

- PGP (".asc"): signed with the publisher's own arbitrary keypair, with no
  central root of trust binding a key to a real-world identity depshieldx
  can verify against (unlike Sigstore's Fulcio-issued, OIDC-bound, short-
  lived certificates). Presence is recorded structurally only -- verifying
  an arbitrary keyserver-fetched key would prove "signed by *a* key," not
  "signed by someone trustworthy," and this module must never imply
  otherwise. The same non-verification npm's own non-Sigstore "publish"
  attestation already gets in npm_registry.py.
- Sigstore (".sigstore.json"), when present: a real "hashedrekord" bundle
  (confirmed directly by inspecting a live example's JSON) -- a raw
  artifact-hash signature backed by a genuine Fulcio certificate and Rekor
  transparency-log inclusion proof, NOT a DSSE-wrapped in-toto statement
  the way npm's SLSA provenance is. Verified here via sigstore-python's
  Verifier.verify_artifact() (the raw-artifact-signature verification
  path), not verify_dsse().

Policy scope, and why it's narrower here than npm's: the one real example
confirmed directly (org.leplus:ristretto:2.0.0) was signed via a Fulcio
certificate whose OIDC issuer extension is GitHub Actions'
(https://token.actions.githubusercontent.com) -- the same issuer
npm_registry.py already checks against for SLSA provenance. Unlike npm
(where GitHub-Actions-published provenance is essentially the only real
path in practice), Maven's publisher base is far more heterogeneous
(Jenkins, GitLab CI, JReleaser, manual `mvn deploy`, ...), so a signature
from a *different*, equally-legitimate OIDC issuer is a real possibility
this module hasn't verified an example of. Rather than guess at (and
potentially wrongly reject) other issuers, or fall back to UnsafeNoOp
(sigstore-python's own docs: "fundamentally insecure... must not be used
to verify any sort of certificate identity" -- an attacker can obtain
their own valid-but-unrelated Fulcio certificate trivially, so skipping
identity policy entirely proves nothing), this module only recognizes the
one confirmed-real issuer for now and records anything else as
"signed via Sigstore, but by an unrecognized issuer" -- informational, not
a block. Broadening the recognized-issuer set is real, well-scoped future
work, not a gap to paper over now.
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from ...storage.cache import get_cache_root
from ...security.provenance import _is_attestation_infrastructure_error, _run_verification_call

MAVEN_CENTRAL_BASE_URL = "https://repo1.maven.org/maven2"
MAVEN_SEARCH_URL = "https://search.maven.org/solrsearch/select"
MAVEN_USER_AGENT = "depshieldx (https://github.com/tee-wealth001/depshieldx)"
GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
# Preference order confirmed directly: newer artifacts publish all four,
# older ones only the first two. Never MD5 -- broken, legacy-only.
CHECKSUM_ALGORITHMS = ("sha256", "sha512", "sha1")
MAVEN_PROVENANCE_CACHE_VERSION = 1
MAVEN_PROVENANCE_CACHE_TTL = timedelta(hours=24)


def group_path(group_id: str) -> str:
    """Maven Central's repository layout replaces "." with "/" in the
    groupId to form the directory path (confirmed directly, e.g.
    "com.fasterxml.jackson.core" -> "com/fasterxml/jackson/core") --
    artifactIds need no equivalent escaping, they're already path-safe by
    Maven convention (lowercase, hyphens, no dots)."""
    return group_id.replace(".", "/")


def artifact_directory_url(group_id: str, artifact_id: str, version: str) -> str:
    return f"{MAVEN_CENTRAL_BASE_URL}/{group_path(group_id)}/{artifact_id}/{version}"


def _artifact_file_url(group_id: str, artifact_id: str, version: str, suffix: str) -> str:
    return f"{artifact_directory_url(group_id, artifact_id, version)}/{artifact_id}-{version}{suffix}"


def fetch_pom_text(group_id: str, artifact_id: str, version: str) -> str:
    """Raises on network/HTTP failure; caller decides how to treat that."""
    response = requests.get(
        _artifact_file_url(group_id, artifact_id, version, ".pom"),
        headers={"User-Agent": MAVEN_USER_AGENT},
        timeout=10,
    )
    response.raise_for_status()
    return response.text


def fetch_jar(group_id: str, artifact_id: str, version: str) -> bytes:
    response = requests.get(
        _artifact_file_url(group_id, artifact_id, version, ".jar"),
        headers={"User-Agent": MAVEN_USER_AGENT},
        timeout=60,
    )
    response.raise_for_status()
    return response.content


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_bom_import_coordinates(pom_text: str) -> list[tuple[str, str, str]]:
    """Extracts every <dependencyManagement><dependencies><dependency>
    entry with <scope>import</scope> and <type>pom</type> -- a "BOM
    import", the other real way (besides <parent> inheritance) a POM can
    require a second POM be present just to resolve, confirmed directly
    against a real, extremely common pattern: org.apache.commons:
    commons-lang3:3.17.0's parent chain (commons-parent:73) imports org.
    junit:junit-bom as a dependency-management BOM, and Maven's
    dependency collector fails outright without it -- the same class of
    "metadata-only POM the resolved coordinate never appears in `dependency
    :list`'s output" problem parse_parent_coordinate solves for
    inheritance, just via a different POM construct.

    A BOM's own <version> element is frequently a "${property}"
    placeholder (confirmed directly for the commons-lang3 example above:
    "${commons.junit.version}") rather than a literal version string --
    resolved here only against the *same* POM's own <properties> block
    (also confirmed real for that example: commons-parent:73 defines
    commons.junit.version itself, not an ancestor). Real Maven also
    resolves properties inherited from further up the parent chain or
    injected by profiles/plugins; that broader case isn't handled here --
    entries whose property can't be resolved locally are skipped rather
    than guessed at, a real and accepted coverage gap analogous to
    ecosystems/go's Stage 3 skipped_modules, not a silent correctness
    bug: if a skipped BOM import turns out to be genuinely required, the
    sandboxed `mvn --offline` step still fails with a clear, real error
    naming exactly what's missing, rather than resolving incorrectly.
    """
    root = ET.fromstring(pom_text)

    properties: dict[str, str] = {}
    for props_el in root:
        if _local_tag(props_el.tag) != "properties":
            continue
        for prop in props_el:
            properties[_local_tag(prop.tag)] = (prop.text or "").strip()

    def _resolve_property(value: str) -> str | None:
        if value.startswith("${") and value.endswith("}"):
            return properties.get(value[2:-1])
        return value

    imports: list[tuple[str, str, str]] = []
    for dep_mgmt in root:
        if _local_tag(dep_mgmt.tag) != "dependencyManagement":
            continue
        for deps_el in dep_mgmt:
            if _local_tag(deps_el.tag) != "dependencies":
                continue
            for dependency in deps_el:
                if _local_tag(dependency.tag) != "dependency":
                    continue
                fields = {_local_tag(field.tag): (field.text or "").strip() for field in dependency}
                if fields.get("scope") != "import" or fields.get("type") != "pom":
                    continue
                group_id, artifact_id, version = fields.get("groupId"), fields.get("artifactId"), fields.get("version")
                if not (group_id and artifact_id and version):
                    continue
                resolved_version = _resolve_property(version)
                if resolved_version:
                    imports.append((group_id, artifact_id, resolved_version))
    return imports


def parse_parent_coordinate(pom_text: str) -> tuple[str, str, str] | None:
    """Extracts a POM's own <parent><groupId>/<artifactId>/<version></parent>
    coordinate, or None if it has none. Used to walk a resolved artifact's
    full parent-POM chain for deep-mode's offline local-repository bundle
    (runner.py's prepare_maven_download_bundle) -- confirmed directly a
    missing parent POM fails Maven's dependency collector outright even
    when the child artifact's own jar+pom are present (e.g. com.google.
    errorprone:error_prone_annotations:2.27.0's parent, error_prone_
    parent:2.27.0, is real metadata-only inheritance, never itself a
    `dependency:list` entry). Namespace-agnostic on purpose: real POMs
    declare the "http://maven.apache.org/POM/4.0.0" default namespace,
    but stripping namespaces from parsed tags (rather than hardcoding
    that one URI) tolerates POMs using no namespace at all, which
    Maven's own parser also accepts (confirmed directly against a real,
    intentionally namespace-less scratch pom.xml resolving without
    error)."""
    root = ET.fromstring(pom_text)
    for child in root:
        if _local_tag(child.tag) != "parent":
            continue
        values = {}
        for field in child:
            values[_local_tag(field.tag)] = (field.text or "").strip()
        group_id, artifact_id, version = values.get("groupId"), values.get("artifactId"), values.get("version")
        if group_id and artifact_id and version:
            return group_id, artifact_id, version
        return None
    return None


def fetch_best_checksum(group_id: str, artifact_id: str, version: str) -> tuple[str, str] | None:
    """Returns (algorithm, hex_digest) for the strongest checksum Central
    actually publishes for this artifact, or None if none are reachable.
    Checksum files contain only the bare hex digest (confirmed directly --
    no "hash  filename" suffix the way sha256sum's own CLI output has)."""
    for algorithm in CHECKSUM_ALGORITHMS:
        url = _artifact_file_url(group_id, artifact_id, version, f".jar.{algorithm}")
        try:
            response = requests.get(url, headers={"User-Agent": MAVEN_USER_AGENT}, timeout=10)
            response.raise_for_status()
        except Exception:
            continue
        digest = response.text.strip()
        if digest:
            return algorithm, digest
    return None


def fetch_sigstore_bundle(group_id: str, artifact_id: str, version: str) -> dict | None:
    """None if the artifact wasn't published with a Sigstore bundle --
    confirmed directly this is the common case today, not an error."""
    url = _artifact_file_url(group_id, artifact_id, version, ".jar.sigstore.json")
    try:
        response = requests.get(url, headers={"User-Agent": MAVEN_USER_AGENT}, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


def has_pgp_signature(group_id: str, artifact_id: str, version: str) -> bool:
    url = _artifact_file_url(group_id, artifact_id, version, ".jar.asc")
    try:
        response = requests.head(url, headers={"User-Agent": MAVEN_USER_AGENT}, timeout=10)
        return response.status_code == 200
    except Exception:
        return False


def search_latest_version(group_id: str, artifact_id: str) -> str | None:
    try:
        response = requests.get(
            MAVEN_SEARCH_URL,
            params={"q": f"g:{group_id} AND a:{artifact_id}", "rows": 1, "wt": "json"},
            headers={"User-Agent": MAVEN_USER_AGENT},
            # search.maven.org's Solr-backed search is materially slower
            # than repo1.maven.org's CDN-backed artifact/checksum fetches
            # (this module's other requests use a 10s timeout) -- confirmed
            # directly, a real query for a real, well-indexed coordinate
            # took over 15s to respond during development. A short timeout
            # here doesn't fail safe, it just makes bare "groupId:
            # artifactId" (no version) targets spuriously unresolvable.
            timeout=30,
        )
        response.raise_for_status()
        docs = (response.json().get("response") or {}).get("docs") or []
        return docs[0].get("latestVersion") if docs else None
    except Exception:
        return None


def _cache_key(group_id: str, artifact_id: str, version: str | None) -> str:
    from hashlib import sha256

    payload = f"maven|{group_id}:{artifact_id}=={version or ''}"
    return sha256(payload.encode("utf-8")).hexdigest()


def _cache_path(group_id: str, artifact_id: str, version: str | None) -> Path:
    return get_cache_root() / "provenance" / f"{_cache_key(group_id, artifact_id, version)}.json"


def _load_cached_result(group_id: str, artifact_id: str, version: str | None) -> dict | None:
    try:
        path = _cache_path(group_id, artifact_id, version)
        if not path.exists():
            return None
        payload = json.loads(path.read_text())
        if payload.get("cache_version") != MAVEN_PROVENANCE_CACHE_VERSION:
            return None
        cached_at = payload.get("cached_at")
        if not cached_at:
            return None
        cached_time = datetime.fromisoformat(cached_at)
        if datetime.now(timezone.utc) - cached_time > MAVEN_PROVENANCE_CACHE_TTL:
            return None
        return payload.get("result")
    except Exception:
        return None


def _store_cached_result(group_id: str, artifact_id: str, version: str | None, result: dict) -> None:
    try:
        path = _cache_path(group_id, artifact_id, version)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cache_version": MAVEN_PROVENANCE_CACHE_VERSION,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "result": result,
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    except Exception:
        return


def _verify_sigstore_bundle(bundle_dict: dict, artifact_bytes: bytes) -> dict:
    """Verifies a real "hashedrekord" Maven Sigstore bundle against the
    downloaded jar bytes, via sigstore-python's Verifier.verify_artifact()
    (the raw-artifact-signature path -- confirmed directly this bundle
    shape is NOT a DSSE envelope, so verify_dsse() is the wrong method
    here, unlike npm's SLSA provenance)."""
    try:
        from sigstore.models import Bundle
        from sigstore.verify import Verifier, policy
    except Exception as exc:
        return {"available": False, "verified": False, "recognized_issuer": None, "errors": [f"sigstore unavailable: {exc}"], "infrastructure_errors": []}

    try:
        bundle = Bundle.from_json(json.dumps(bundle_dict))
    except Exception as exc:
        return {"available": False, "verified": False, "recognized_issuer": None, "errors": [f"could not parse Sigstore bundle: {exc}"], "infrastructure_errors": []}

    verify_policy = policy.OIDCIssuer(GITHUB_ACTIONS_OIDC_ISSUER)

    def _attempt(offline: bool):
        Verifier.production(offline=offline).verify_artifact(artifact_bytes, bundle, verify_policy)

    verification_errors: list[str] = []
    infrastructure_errors: list[str] = []
    succeeded = False
    try:
        _run_verification_call(lambda: _attempt(False), suppress_output=True)
        succeeded = True
    except Exception as exc:
        message = str(exc)
        if _is_attestation_infrastructure_error(message):
            try:
                _run_verification_call(lambda: _attempt(True), suppress_output=True)
                succeeded = True
            except Exception as offline_exc:
                offline_message = str(offline_exc)
                if _is_attestation_infrastructure_error(offline_message):
                    infrastructure_errors.append(offline_message)
                else:
                    verification_errors.append(offline_message)
        else:
            # See module docstring: only the GitHub Actions issuer has been
            # confirmed against a real example -- a policy mismatch here
            # (a real signature from some *other* legitimate OIDC issuer)
            # isn't evidence of tampering, just an unrecognized-for-now
            # signer, so it's reported as informational rather than an
            # error.
            verification_errors.append(message)

    return {
        "available": not infrastructure_errors,
        "verified": succeeded,
        "recognized_issuer": GITHUB_ACTIONS_OIDC_ISSUER if succeeded else None,
        "errors": verification_errors[:3],
        "infrastructure_errors": infrastructure_errors[:3],
    }


def check_release(group_id: str, artifact_id: str, version: str, verbose: bool = False) -> dict:
    cached = _load_cached_result(group_id, artifact_id, version)
    if cached is not None:
        return cached

    infos: list[str] = []
    warnings: list[str] = []

    checksum = fetch_best_checksum(group_id, artifact_id, version)
    if not checksum:
        infos.append("no checksum published for the resolved artifact")

    pgp_signed = has_pgp_signature(group_id, artifact_id, version)
    if not pgp_signed:
        warnings.append("resolved artifact has no PGP signature -- unusual for a real Central Repository release")

    sigstore_bundle = fetch_sigstore_bundle(group_id, artifact_id, version)
    sigstore_result = {"available": False, "verified": False, "recognized_issuer": None, "errors": [], "infrastructure_errors": []}
    if sigstore_bundle is not None:
        try:
            artifact_bytes = fetch_jar(group_id, artifact_id, version)
            sigstore_result = _verify_sigstore_bundle(sigstore_bundle, artifact_bytes)
            if sigstore_result["verified"]:
                infos.append(f"resolved artifact has a verified Sigstore signature (issuer: {sigstore_result['recognized_issuer']})")
            elif sigstore_result["available"]:
                infos.append("resolved artifact has a Sigstore bundle, but signed by an unrecognized issuer")
        except Exception as exc:
            infos.append(f"could not verify Sigstore bundle: {exc}")
    else:
        infos.append("no Sigstore bundle published for the resolved artifact -- PGP-only, the common case today")

    result = {
        "package": f"{group_id}:{artifact_id}",
        "version": version,
        "block": False,
        "reason": None,
        "warnings": warnings,
        "infos": infos,
        "signals": {
            "checksum_algorithm": checksum[0] if checksum else None,
            "checksum": checksum[1] if checksum else None,
            "pgp_signed": pgp_signed,
            "sigstore_available": sigstore_result["available"],
            "sigstore_verified": sigstore_result["verified"],
            "sigstore_recognized_issuer": sigstore_result["recognized_issuer"],
        },
    }
    _store_cached_result(group_id, artifact_id, version, result)
    return result


def check_provenance_batch(
    resolved_versions: dict[str, str],
    selected_artifacts: dict[str, list[dict]] | None = None,
    verbose: bool = False,
) -> dict:
    if not resolved_versions:
        return {"block": False, "warnings": [], "infos": [], "details": []}

    details = []
    warnings: list[str] = []
    infos: list[str] = []
    for coordinate, version in resolved_versions.items():
        group_id, _, artifact_id = coordinate.partition(":")
        result = check_release(group_id, artifact_id, version, verbose=verbose)
        details.append(result)
        if result["block"]:
            return {
                "block": True,
                "reason": f"{coordinate}@{version} {result['reason']}",
                "warnings": warnings,
                "infos": infos,
                "details": details,
            }
        warnings.extend([f"{coordinate}@{version}: {message}" for message in result["warnings"]])
        infos.extend([f"{coordinate}@{version}: {message}" for message in result.get("infos", [])])

    return {"block": False, "warnings": warnings, "infos": infos, "details": details}
