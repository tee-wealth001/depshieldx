"""npm registry client: package metadata fetch + cryptographic provenance
verification.

npm's dist.attestations field (from the package metadata endpoint) only
carries a predicateType and a URL -- confirmed directly against the live
registry -- the actual Sigstore bundle lives at a separate endpoint,
NPM_ATTESTATIONS_URL. That endpoint returns two different attestations per
published version, confirmed directly against a real npm package published
with --provenance (the `sigstore` npm package itself, chosen because it's a
well-known real example):

- predicateType "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"
  ("publish" attestation): signed with npm registry's own fixed key
  (verificationMaterial.publicKey), not a Fulcio-issued certificate bound to
  an OIDC identity. That's a different, npm-registry-specific trust model
  the generic `sigstore` Verifier can't check (it verifies Fulcio certs
  against Rekor, not a static publisher key) -- recorded structurally only.
- predicateType "https://slsa.dev/provenance/v1" (SLSA provenance): a real
  Fulcio-issued short-lived certificate bound to the publishing GitHub
  Actions run's OIDC identity, with a real Rekor transparency-log inclusion
  proof -- the same trust model PyPI's Trusted Publishing attestations use.
  This is the one this module cryptographically verifies, via the generic
  `sigstore` package (already a transitive dependency of pypi-attestations,
  declared directly here) rather than anything npm-specific.

Policy: unlike PyPI's Trusted Publisher feature, npm has no per-package
pre-registered publisher allowlist to check the certificate against, so the
policy here checks that the Fulcio certificate's OIDC issuer extension is
GitHub Actions' issuer URL -- proving the attestation was signed by a real
GitHub Actions workflow run via Sigstore's short-lived-certificate/
transparency-log model, not a hardcoded allowlist of specific
repositories.

Subject digest match: the in-toto statement's subject digest is compared
against dist.integrity (base64 SRI, decoded to hex) rather than a fresh
tarball download -- ecosystems/npm.py's fetch_artifact already independently
verifies downloaded bytes against that same dist.integrity value via SRI
check at actual install time, so matching against it here (confirmed
byte-for-byte identical to the attestation's subject digest against a real
package) still ties the attestation back to the real installed bytes,
without a redundant download purely for verification purposes.
"""

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from ...storage.cache import get_cache_root
from ...security.provenance import _is_attestation_infrastructure_error, _run_verification_call

NPM_REGISTRY_PACKAGE_URL = "https://registry.npmjs.org/{package}"
NPM_ATTESTATIONS_URL = "https://registry.npmjs.org/-/npm/v1/attestations/{package}@{version}"
NPM_SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
NPM_PROVENANCE_CACHE_VERSION = 2
NPM_PROVENANCE_CACHE_TTL = timedelta(hours=24)


def _cache_key(package_name: str, version: str | None) -> str:
    from hashlib import sha256

    payload = f"npm|{package_name}=={version or ''}"
    return sha256(payload.encode("utf-8")).hexdigest()


def _cache_path(package_name: str, version: str | None) -> Path:
    return get_cache_root() / "provenance" / f"{_cache_key(package_name, version)}.json"


def _load_cached_result(package_name: str, version: str | None) -> dict | None:
    try:
        path = _cache_path(package_name, version)
        if not path.exists():
            return None
        payload = json.loads(path.read_text())
        if payload.get("cache_version") != NPM_PROVENANCE_CACHE_VERSION:
            return None
        cached_at = payload.get("cached_at")
        if not cached_at:
            return None
        cached_time = datetime.fromisoformat(cached_at)
        if datetime.now(timezone.utc) - cached_time > NPM_PROVENANCE_CACHE_TTL:
            return None
        return payload.get("result")
    except Exception:
        return None


def _store_cached_result(package_name: str, version: str | None, result: dict) -> None:
    try:
        path = _cache_path(package_name, version)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cache_version": NPM_PROVENANCE_CACHE_VERSION,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "result": result,
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    except Exception:
        return


def fetch_package_metadata(package_name: str) -> dict:
    """Raises on network/HTTP failure; caller decides how to treat that."""
    response = requests.get(NPM_REGISTRY_PACKAGE_URL.format(package=package_name), timeout=5)
    response.raise_for_status()
    return response.json()


def fetch_attestation_bundles(package_name: str, version: str) -> list[dict]:
    """Raises on network/HTTP failure; caller decides how to treat that."""
    url = NPM_ATTESTATIONS_URL.format(package=package_name, version=version)
    response = requests.get(url, timeout=5)
    response.raise_for_status()
    return response.json().get("attestations") or []


def _integrity_digest_hex(dist: dict, algorithm: str = "sha512") -> str | None:
    integrity = (dist.get("integrity") or "").strip()
    prefix = f"{algorithm}-"
    if not integrity.startswith(prefix):
        return None
    try:
        return base64.b64decode(integrity[len(prefix):]).hex()
    except Exception:
        return None


def _npm_purl(package_name: str, version: str) -> str:
    """Build the exact purl npm's own attestations use as their subject
    name. Reproduced directly against a real scoped package's attestation
    (@npmcli/agent): npm percent-encodes the leading "@" of a scope as
    "%40" (pkg:npm/%40npmcli/agent@5.0.2), not the raw "@" -- using the raw
    "@" here made subject-name matching fail for every scoped package
    (@babel/*, @types/*, etc.), a very common npm pattern, not an edge case.
    """
    if package_name.startswith("@"):
        return f"pkg:npm/%40{package_name[1:]}@{version}"
    return f"pkg:npm/{package_name}@{version}"


def _is_bundle_format_unsupported_error(message: str) -> bool:
    """Older npm-published Sigstore bundles use Rekor tlog entry
    kinds/bundle mediaType versions the installed `sigstore` library's
    integrated-time check doesn't fully support -- confirmed directly
    against a real, legitimate package (@tufjs/canonical-json@2.0.0, whose
    bundle uses an "intoto" 0.0.2 tlog entry and mediaType version=0.1,
    unlike newer packages' "dsse" 0.0.1 entries): verify_dsse fails
    identically online and offline with this exact message. A library/
    format compatibility gap, not evidence the package or its attestation
    is untrustworthy -- must be treated as unavailable, not a verification
    failure, or a large fraction of legitimate older npm attestations would
    be false-blocked.
    """
    return "integrated time only supported for" in message.lower()


def _parse_attestation_entry(entry: dict) -> dict:
    bundle = entry.get("bundle") or {}
    verification_material = bundle.get("verificationMaterial") or {}
    return {
        "predicate_type": entry.get("predicateType"),
        # See module docstring: only the SLSA provenance entry (a real
        # Fulcio cert) is cryptographically verifiable here -- the npm
        # "publish" entry is signed with npm's own fixed key instead.
        "signed_by_certificate": bool(verification_material.get("certificate")),
    }


def _verify_slsa_bundle(bundle_dict: dict, expected_sha512_hex: str | None, purl: str, verbose: bool = False) -> dict:
    try:
        from sigstore.models import Bundle
        from sigstore.verify import Verifier, policy
    except Exception as exc:
        return {"available": False, "verified": False, "errors": [f"sigstore unavailable: {exc}"], "infrastructure_errors": []}

    try:
        bundle = Bundle.from_json(json.dumps(bundle_dict))
    except Exception as exc:
        return {"available": False, "verified": False, "errors": [f"could not parse Sigstore bundle: {exc}"], "infrastructure_errors": []}

    verify_policy = policy.OIDCIssuer(GITHUB_ACTIONS_OIDC_ISSUER)

    def _attempt(offline: bool):
        return Verifier.production(offline=offline).verify_dsse(bundle, verify_policy)

    def _is_infrastructure_error(message: str) -> bool:
        return _is_attestation_infrastructure_error(message) or _is_bundle_format_unsupported_error(message)

    verification_errors: list[str] = []
    infrastructure_errors: list[str] = []
    payload = None
    try:
        _media_type, payload = _run_verification_call(lambda: _attempt(False), suppress_output=not verbose)
    except Exception as exc:
        message = str(exc)
        if _is_infrastructure_error(message):
            if _is_bundle_format_unsupported_error(message):
                # Not network-related -- retrying offline would just fail
                # identically (confirmed directly), so skip straight to
                # recording it as an infrastructure limitation.
                infrastructure_errors.append(message)
            else:
                try:
                    _media_type, payload = _run_verification_call(lambda: _attempt(True), suppress_output=not verbose)
                except Exception as offline_exc:
                    offline_message = str(offline_exc)
                    if _is_infrastructure_error(offline_message):
                        infrastructure_errors.append(offline_message)
                    else:
                        verification_errors.append(offline_message)
        else:
            verification_errors.append(message)

    if payload is None:
        return {
            "available": bool(verification_errors),
            "verified": False,
            "errors": verification_errors[:3],
            "infrastructure_errors": infrastructure_errors[:3],
        }

    try:
        statement = json.loads(payload)
    except Exception as exc:
        return {"available": True, "verified": False, "errors": [f"could not parse DSSE payload: {exc}"], "infrastructure_errors": []}

    subjects = statement.get("subject") or []
    if expected_sha512_hex and not any(
        (subject.get("digest") or {}).get("sha512") == expected_sha512_hex for subject in subjects
    ):
        return {
            "available": True,
            "verified": False,
            "errors": ["attestation subject digest does not match the resolved package's integrity digest"],
            "infrastructure_errors": [],
        }
    if not any(subject.get("name") == purl for subject in subjects):
        return {
            "available": True,
            "verified": False,
            "errors": ["attestation subject name does not match the resolved package"],
            "infrastructure_errors": [],
        }

    return {"available": True, "verified": True, "errors": [], "infrastructure_errors": []}


def _attestation_signals(package_name: str, version: str, dist: dict, verbose: bool = False) -> tuple[dict, list[str]]:
    # npm resolves exactly one tarball per package@version (unlike PyPI's
    # wheel+sdist multiplicity) -- cli/output.py's summary formatter reads
    # *_file_count keys either way, so those are always 0 or 1 here.
    filename = f"{package_name.replace('/', '-')}-{version}.tgz"

    try:
        entries = fetch_attestation_bundles(package_name, version)
    except Exception:
        entries = []

    parsed = [_parse_attestation_entry(entry) for entry in entries]
    slsa_entry = next((entry for entry in entries if entry.get("predicateType") == NPM_SLSA_PREDICATE_TYPE), None)

    messages: list[str] = []
    if not entries:
        messages.append("resolved release has no npm provenance attestations")
        return (
            {
                "has_attestations": False,
                "fully_verified_attestations": False,
                "attestation_verification_available": False,
                "verified_attestation_count": 0,
                "attested_file_count": 0,
                "verified_attestation_file_count": 0,
                "selected_file_count": 1,
                "verification_failure": None,
                "verification_unavailable": None,
                "trusted_publisher": False,
                "attestation_predicate_types": [],
            },
            messages,
        )

    verification: dict | None = None
    if slsa_entry is None:
        messages.append("resolved release has npm attestations but none use the verifiable SLSA provenance predicate")
    else:
        purl = _npm_purl(package_name, version)
        expected_digest = _integrity_digest_hex(dist)
        if not expected_digest:
            messages.append("resolved release is missing a sha512 integrity digest to match against its attestation")
        verification = _verify_slsa_bundle(slsa_entry["bundle"], expected_digest, purl, verbose=verbose)

    verified = bool(verification and verification["verified"])
    verification_available = bool(verification and verification["available"])
    verification_failure = None
    verification_unavailable = None
    if verification and not verification["verified"]:
        if verification["errors"]:
            verification_failure = {"filename": filename, "error": verification["errors"][0]}
        elif verification["infrastructure_errors"]:
            verification_unavailable = {"filename": filename, "error": verification["infrastructure_errors"][0]}

    if slsa_entry is not None:
        if verification_available and not verified:
            messages.append("cryptographic attestation verification failed for the resolved release")
        elif not verification_available:
            messages.append("cryptographic attestation verification unavailable")

    return (
        {
            "has_attestations": True,
            "fully_verified_attestations": verified,
            "attestation_verification_available": verification_available,
            "verified_attestation_count": 1 if verified else 0,
            "attested_file_count": 1,
            "verified_attestation_file_count": 1 if verified else 0,
            "selected_file_count": 1,
            "verification_failure": verification_failure,
            "verification_unavailable": verification_unavailable,
            # npm has no per-package pre-registered publisher allowlist the
            # way PyPI's Trusted Publishing does -- "trusted_publisher" here
            # means "verified via a real GitHub Actions OIDC-issued Fulcio
            # certificate", matching this module's actual policy (see
            # module docstring), not a repository allowlist match.
            "trusted_publisher": verified,
            "attestation_predicate_types": sorted({item["predicate_type"] for item in parsed if item["predicate_type"]}),
        },
        messages,
    )


def _unavailable_result(package_name: str, version: str | None) -> dict:
    return {
        "package": package_name,
        "version": version,
        "block": False,
        "reason": None,
        "warnings": [],
        "infos": ["resolved release metadata is missing on the npm registry"],
        "signals": {"unavailable": True},
    }


def check_release(package_name: str, version: str | None = None, verbose: bool = False) -> dict:
    cached = _load_cached_result(package_name, version)
    if cached is not None:
        return cached

    try:
        data = fetch_package_metadata(package_name)
    except Exception:
        # Don't cache network failures -- they should be retried on the next run.
        return _unavailable_result(package_name, version)

    versions = data.get("versions") or {}
    resolved_version = version or (data.get("dist-tags") or {}).get("latest")
    version_meta = versions.get(resolved_version) if resolved_version else None

    if not version_meta:
        result = _unavailable_result(package_name, resolved_version)
        _store_cached_result(package_name, version, result)
        return result

    infos: list[str] = []
    dist = version_meta.get("dist") or {}

    deprecated_message = version_meta.get("deprecated")
    if deprecated_message:
        infos.append(f"resolved version is deprecated: {deprecated_message}")

    has_homepage = bool(version_meta.get("homepage") or version_meta.get("repository"))
    if not has_homepage:
        infos.append("package metadata has no homepage or repository URL")

    has_contact = bool(version_meta.get("author") or version_meta.get("maintainers"))
    if not has_contact:
        infos.append("package metadata has no author or maintainer contact")

    has_integrity = bool(dist.get("integrity") or dist.get("shasum"))
    if not has_integrity:
        infos.append("resolved release is missing an integrity/shasum digest")

    attestation_signals, attestation_messages = _attestation_signals(
        package_name, resolved_version, dist, verbose=verbose
    )
    infos.extend(attestation_messages)

    block = False
    reason = None
    # Mirrors provenance.py's exact PyPI policy: block only when
    # verification was actually attempted and failed, never purely on "no
    # attestations" -- most npm packages don't publish with --provenance at
    # all, and that alone isn't evidence of anything suspicious.
    if (
        attestation_signals["attestation_verification_available"]
        and attestation_signals["has_attestations"]
        and not attestation_signals["fully_verified_attestations"]
    ):
        block = True
        reason = "resolved release attestation verification failed"

    result = {
        "package": package_name,
        "version": resolved_version,
        "block": block,
        "reason": reason,
        "warnings": [],
        "infos": infos,
        "signals": {
            "has_homepage": has_homepage,
            "has_contact": has_contact,
            "deprecated": bool(deprecated_message),
            "has_integrity_digest": has_integrity,
            "unavailable": False,
            **attestation_signals,
        },
    }
    _store_cached_result(package_name, version, result)
    return result


def check_provenance_batch(
    resolved_versions: dict[str, str],
    selected_artifacts: dict[str, list[dict]] | None = None,
    verbose: bool = False,
) -> dict:
    if not resolved_versions:
        return {"block": False, "warnings": [], "infos": [], "details": []}

    ordered_items = list(resolved_versions.items())
    details = []
    warnings: list[str] = []
    infos: list[str] = []
    for package_name, version in ordered_items:
        result = check_release(package_name, version, verbose=verbose)
        details.append(result)
        if result["block"]:
            return {
                "block": True,
                "reason": f"{package_name}@{version} {result['reason']}",
                "warnings": warnings,
                "infos": infos,
                "details": details,
            }
        warnings.extend([f"{package_name}@{version}: {message}" for message in result["warnings"]])
        infos.extend([f"{package_name}@{version}: {message}" for message in result.get("infos", [])])

    return {"block": False, "warnings": warnings, "infos": infos, "details": details}
