import hmac
import stat
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote

from .cache import get_cache_root


RECEIPT_SCHEMA_VERSION = 2


class ReceiptUnavailableError(RuntimeError):
    pass


def _private_root_candidates(env_var: str, suffix: str) -> list[Path]:
    override = os.environ.get(env_var)
    if override:
        return [Path(override)]

    candidates = [get_cache_root() / suffix]

    try:
        uid = os.getuid()
    except AttributeError:
        uid = os.getpid()

    temp_root = Path(tempfile.gettempdir()) / f"depshieldx-{suffix}-{uid}"
    if temp_root not in candidates:
        candidates.append(temp_root)
    return candidates


def _receipts_root_candidates() -> list[Path]:
    return _private_root_candidates("DEPSHIELDX_RECEIPTS_DIR", "receipts")


def _signing_root_candidates() -> list[Path]:
    return _private_root_candidates("DEPSHIELDX_SIGNING_KEY_DIR", "keys")


def _ensure_private_directory(candidates: list[Path], label: str) -> Path:
    errors = []
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                os.chmod(candidate, 0o700)
            except OSError:
                pass
            return candidate
        except OSError as exc:
            errors.append(f"{candidate}: {exc}")
    detail = "; ".join(errors) if errors else f"no writable {label} directory candidates"
    raise ReceiptUnavailableError(f"unable to create {label} store ({detail})")


def _ensure_receipts_root() -> Path:
    return _ensure_private_directory(_receipts_root_candidates(), "receipt")


def _ensure_signing_root() -> Path:
    return _ensure_private_directory(_signing_root_candidates(), "signing key")


def _signing_key_path(root: Path | None = None) -> Path:
    if root is None:
        root = _ensure_signing_root()
    return root / "signing.key"


def _canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _load_or_create_signing_key() -> bytes:
    root = _ensure_signing_root()
    path = _signing_key_path(root)
    if path.exists():
        return _load_existing_signing_key(path)

    key = secrets.token_bytes(32)
    return _write_signing_key(path, key)


def _write_signing_key(path: Path, key: bytes) -> bytes:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return _load_existing_signing_key(path)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(key.hex() + "\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return key
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _load_existing_signing_key(path: Path) -> bytes:
    _assert_secure_signing_key_path(path)
    return bytes.fromhex(path.read_text().strip())


def _assert_secure_signing_key_path(path: Path) -> None:
    try:
        file_stat = os.lstat(path)
    except OSError as exc:
        raise ReceiptUnavailableError(f"unable to inspect signing key: {exc}") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise ReceiptUnavailableError("signing key path is not a regular file")
    if stat.S_ISLNK(file_stat.st_mode):
        raise ReceiptUnavailableError("signing key path must not be a symlink")
    if os.name != "nt" and file_stat.st_mode & 0o077:
        raise ReceiptUnavailableError("signing key permissions are too broad; expected 0600")


def _sign_payload(payload: dict) -> dict:
    key = _load_or_create_signing_key()
    signature = hmac.new(key, _canonical_json(payload).encode("utf-8"), sha256).hexdigest()
    key_id = sha256(key).hexdigest()[:16]
    return {
        "algorithm": "hmac-sha256",
        "key_id": key_id,
        "value": signature,
    }


def _decision_for_report(report: dict) -> str:
    install = report.get("install") or {}
    if install.get("success"):
        return "allowed"
    if install.get("blocked"):
        return "blocked"
    if install.get("skipped"):
        return "skipped"
    return "failed"


def _result_summary(result: dict | None) -> dict:
    result = result or {}
    return {
        "block": bool(result.get("block")),
        "warning_count": len(result.get("warnings") or []),
        "info_count": len(result.get("infos") or []),
        "reason": result.get("reason"),
    }


def _report_digest(report: dict) -> str:
    return sha256(_canonical_json(report).encode("utf-8")).hexdigest()


def _safe_receipt_basename(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in value.strip())
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    cleaned = cleaned.strip("-")
    return cleaned or "report"


def _normalize_name(name: str) -> str:
    return name.strip().lower().replace("-", "_")


def _package_name_from_requirement(target: str | None) -> str | None:
    if not target:
        return None
    value = target.strip()
    if not value or value.startswith(("-", ".", "/", "~")) or "://" in value or "/" in value or "\\" in value:
        return None
    match = __import__("re").match(r"^([A-Za-z0-9_.-]+)", value)
    return match.group(1) if match else None


def _resolved_requested_packages(resolution: dict) -> list[tuple[str, str, str]]:
    requested_targets = resolution.get("requested_targets") or []
    resolved_versions = resolution.get("resolved_versions") or {}
    resolved_lookup = {
        _normalize_name(name): (name, version)
        for name, version in resolved_versions.items()
        if version
    }

    requested_packages = []
    seen = set()
    for target in requested_targets:
        requested_name = _package_name_from_requirement(target)
        if not requested_name:
            continue
        resolved = resolved_lookup.get(_normalize_name(requested_name))
        if not resolved:
            continue
        key = (resolved[0], resolved[1])
        if key in seen:
            continue
        seen.add(key)
        requested_packages.append((resolved[0], resolved[1], target))
    return requested_packages


def _filter_messages_for_package(messages: list[str] | None, package_name: str, package_version: str) -> list[str]:
    prefix = f"{package_name}=={package_version}: "
    filtered = []
    for message in messages or []:
        if message.startswith(prefix):
            filtered.append(message[len(prefix):])
    return filtered


def _package_source_summary(scan: dict | None, package_name: str) -> dict:
    threat_intelligence = (scan or {}).get("threat_intelligence") or {}
    normalized_package = _normalize_name(package_name)
    summary = {
        "osv": {"current_count": 0, "historical_count": 0},
        "cisa-kev": {"current_count": 0, "historical_count": 0, "unverified_count": 0},
        "github-advisories": {"current_count": 0},
        "deps-dev": {"advisory_count": 0, "checked_records": 0},
    }

    for key, pkg_data in (threat_intelligence.get("multi_source_cves") or {}).items():
        if _normalize_name(key) != normalized_package:
            continue
        for vuln in pkg_data.get("current", []):
            source = vuln.get("source", "unknown")
            summary.setdefault(source, {"current_count": 0, "historical_count": 0})
            summary[source]["current_count"] = summary[source].get("current_count", 0) + 1
        for vuln in pkg_data.get("historical", []):
            source = vuln.get("source", "unknown")
            summary.setdefault(source, {"current_count": 0, "historical_count": 0})
            summary[source]["historical_count"] = summary[source].get("historical_count", 0) + 1
        for vuln in pkg_data.get("unverified", []):
            source = vuln.get("source", "unknown")
            summary.setdefault(source, {"current_count": 0, "historical_count": 0, "unverified_count": 0})
            summary[source]["unverified_count"] = summary[source].get("unverified_count", 0) + 1

    github_hits = [
        hit for hit in (threat_intelligence.get("github_advisories") or {}).get("hits", [])
        if _normalize_name(hit.get("package") or "") == normalized_package
    ]
    if github_hits:
        summary["github-advisories"]["current_count"] = len(github_hits)

    deps_hits = [
        hit for hit in (threat_intelligence.get("deps_dev") or {}).get("hits", [])
        if _normalize_name(hit.get("package") or "") == normalized_package
    ]
    if deps_hits:
        summary["deps-dev"]["checked_records"] = len(deps_hits)
        summary["deps-dev"]["advisory_count"] = sum(hit.get("advisory_count", 0) for hit in deps_hits)

    return summary


def _package_historical_vulnerabilities(scan: dict | None, package_name: str, package_version: str) -> list[dict]:
    threat_intelligence = (scan or {}).get("threat_intelligence") or {}
    normalized_package = _normalize_name(package_name)
    historical = []
    for key, pkg_data in (threat_intelligence.get("multi_source_cves") or {}).items():
        if _normalize_name(key) != normalized_package:
            continue
        for vuln in pkg_data.get("historical", []):
            historical.append(
                {
                    "package": package_name,
                    "package_version": package_version,
                    "cve_id": vuln.get("cve_id"),
                    "source": vuln.get("source"),
                    "affected_versions": vuln.get("affected_versions") or [],
                    "fixed_in_version": vuln.get("fixed_in_version"),
                    "severity": vuln.get("severity"),
                    "summary": vuln.get("summary"),
                    "aliases": vuln.get("aliases") or [],
                }
            )
    return historical


def _project_url(package_name: str, package_version: str) -> str:
    return f"https://pypi.org/project/{quote(package_name)}/{quote(package_version)}/"


def _package_receipt_summary(report: dict, package_name: str, package_version: str, requested_target: str) -> dict:
    resolution = report.get("resolution") or {}
    provenance = report.get("provenance") or {}
    sandbox = report.get("sandbox") or {}
    install = dict(report.get("install") or {})
    selected_artifacts = (resolution.get("selected_artifacts") or {}).get(package_name) or []
    provenance_detail = next(
        (detail for detail in provenance.get("details") or [] if _normalize_name(detail.get("package") or "") == _normalize_name(package_name)),
        None,
    )

    if install.get("success"):
        install["target"] = f"{package_name}=={package_version}"

    summary = {
        "package": {
            "name": package_name,
            "version": package_version,
            "requested": True,
            "requested_target": requested_target,
            "project_url": _project_url(package_name, package_version),
            "selected_artifact_count": len(selected_artifacts),
            "selected_artifacts": selected_artifacts,
        },
        "resolution": {
            "install_target": f"{package_name}=={package_version}",
            "requested_targets": resolution.get("requested_targets") or [],
            "resolved_package_count": len(resolution.get("packages") or []),
            "source_type": resolution.get("source_type"),
            "resolution_succeeded": resolution.get("resolution_succeeded", True),
            "resolution_error": resolution.get("resolution_error"),
        },
        "install": install,
    }

    if report.get("scan") is not None:
        summary["scan"] = {
            **_result_summary(report.get("scan")),
            "warnings": _filter_messages_for_package((report.get("scan") or {}).get("warnings"), package_name, package_version),
            "infos": _filter_messages_for_package((report.get("scan") or {}).get("infos"), package_name, package_version),
            "sources": _package_source_summary(report.get("scan"), package_name),
            "historical_fixed": _package_historical_vulnerabilities(report.get("scan"), package_name, package_version),
        }
    if report.get("provenance") is not None:
        summary["provenance"] = {
            **_result_summary(report.get("provenance")),
            "warnings": _filter_messages_for_package((report.get("provenance") or {}).get("warnings"), package_name, package_version),
            "infos": _filter_messages_for_package((report.get("provenance") or {}).get("infos"), package_name, package_version),
            "signals": (provenance_detail or {}).get("signals") or {},
        }
    if report.get("sandbox") is not None:
        summary["sandbox"] = {
            "success": sandbox.get("success"),
            "error_type": sandbox.get("error_type"),
            "backend": (sandbox.get("isolation") or {}).get("backend"),
            "trust_level": (sandbox.get("trust") or {}).get("level"),
        }
    return summary


def build_receipt(report: dict, *, package_name: str | None = None, package_version: str | None = None, requested_target: str | None = None) -> dict:
    report_without_receipt = {key: value for key, value in report.items() if key != "receipt"}
    created_at = datetime.now(timezone.utc).isoformat()
    risk = report_without_receipt.get("risk") or {}
    resolution = report_without_receipt.get("resolution") or {}
    sandbox = report_without_receipt.get("sandbox") or {}
    if package_name and package_version and requested_target:
        summary = _package_receipt_summary(report_without_receipt, package_name, package_version, requested_target)
    else:
        summary = {
            "resolution": {
                "install_target": resolution.get("install_target"),
                "requested_targets": resolution.get("requested_targets") or [],
                "resolved_package_count": len(resolution.get("packages") or []),
                "source_type": resolution.get("source_type"),
                "resolution_succeeded": resolution.get("resolution_succeeded", True),
                "resolution_error": resolution.get("resolution_error"),
            },
            "install": report_without_receipt.get("install") or {},
        }
        if report_without_receipt.get("scan") is not None:
            summary["scan"] = _result_summary(report_without_receipt.get("scan"))
        if report_without_receipt.get("provenance") is not None:
            summary["provenance"] = _result_summary(report_without_receipt.get("provenance"))
        if report_without_receipt.get("policy") is not None:
            summary["policy"] = _result_summary(report_without_receipt.get("policy"))
        if report_without_receipt.get("sandbox") is not None:
            summary["sandbox"] = {
                "success": sandbox.get("success"),
                "error_type": sandbox.get("error_type"),
                "backend": (sandbox.get("isolation") or {}).get("backend"),
                "trust_level": (sandbox.get("trust") or {}).get("level"),
            }
    if risk:
        summary["risk"] = {
            "score": risk.get("score", 0),
            "level": risk.get("level", "unknown"),
            "top_reason": ((risk.get("reasons") or [{}])[0]).get("message"),
        }
    payload = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "created_at": created_at,
        "decision": _decision_for_report(report_without_receipt),
        "ecosystem": report_without_receipt.get("ecosystem", "pypi"),
        "package": package_name or report_without_receipt.get("package"),
        "package_version": package_version,
        "mode": report_without_receipt.get("mode"),
        "requested_target": requested_target,
        "requested_at": report_without_receipt.get("requested_at"),
        "report_digest": _report_digest(report_without_receipt),
        "summary": summary,
    }
    receipt_id = sha256(_canonical_json(payload).encode("utf-8")).hexdigest()[:16]
    signed_payload = {**payload, "receipt_id": receipt_id}
    return {
        **signed_payload,
        "signature": _sign_payload(signed_payload),
    }


def write_receipt(report: dict) -> dict:
    try:
        root = _ensure_receipts_root()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        requested_packages = _resolved_requested_packages((report.get("resolution") or {}))
        receipt_specs = requested_packages or [(None, None, None)]
        receipt_entries = []
        for package_name, package_version, requested_target in receipt_specs:
            receipt = build_receipt(
                report,
                package_name=package_name,
                package_version=package_version,
                requested_target=requested_target,
            )
            package = _safe_receipt_basename(
                f"{receipt.get('package') or 'report'}-{receipt.get('package_version') or ''}"
            )
            path = root / f"{timestamp}-{package}-{receipt['receipt_id']}.json"
            path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
            receipt_entries.append(
                {
                    "package": receipt.get("package"),
                    "package_version": receipt.get("package_version"),
                    "receipt_id": receipt["receipt_id"],
                    "decision": receipt["decision"],
                    "path": str(path),
                    "signature": receipt["signature"]["value"],
                }
            )

        if len(receipt_entries) == 1:
            entry = receipt_entries[0]
            return {
                "receipt_id": entry["receipt_id"],
                "decision": entry["decision"],
                "path": entry["path"],
                "signature": entry["signature"],
            }
        return {
            "decision": receipt_entries[0]["decision"] if receipt_entries else "unavailable",
            "receipt_count": len(receipt_entries),
            "paths": [entry["path"] for entry in receipt_entries],
            "receipts": receipt_entries,
        }
    except (OSError, ValueError) as exc:
        raise ReceiptUnavailableError(str(exc)) from exc


def verify_receipt(path: str | Path) -> dict:
    receipt_path = Path(path)
    receipt = json.loads(receipt_path.read_text())
    signature = receipt.get("signature") or {}
    signed_payload = {key: value for key, value in receipt.items() if key != "signature"}
    expected = _sign_payload(signed_payload)
    valid = (
        signature.get("algorithm") == expected["algorithm"]
        and signature.get("key_id") == expected.get("key_id")
        and hmac.compare_digest(signature.get("value", ""), expected["value"])
    )
    return {
        "valid": valid,
        "receipt": receipt,
        "path": str(receipt_path),
    }


def list_receipts(limit: int = 20) -> list[dict]:
    try:
        root = _ensure_receipts_root()
    except ReceiptUnavailableError:
        return []
    if not root.exists():
        return []
    items = []
    for path in sorted(root.glob("*.json"), reverse=True)[:limit]:
        try:
            receipt = json.loads(path.read_text())
        except Exception:
            continue
        items.append(
            {
                "receipt_id": receipt.get("receipt_id"),
                "created_at": receipt.get("created_at"),
                "decision": receipt.get("decision"),
                "package": receipt.get("package"),
                "path": str(path),
            }
        )
    return items


def delete_receipts() -> int:
    try:
        root = _ensure_receipts_root()
    except ReceiptUnavailableError:
        return 0
    if not root.exists():
        return 0
    deleted = 0
    for path in root.glob("*.json"):
        try:
            path.unlink()
            deleted += 1
        except OSError:
            continue
    return deleted
