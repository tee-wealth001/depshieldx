"""Receipt/cache/provenance data formatting for the local UI's /api/cache endpoint."""

import json
from datetime import datetime, timezone
from pathlib import Path

from ...cache import get_cache_root
from ...receipts import _receipts_root_candidates


def _safe_json_load(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _existing_receipts_root() -> Path | None:
    for candidate in _receipts_root_candidates():
        if candidate.exists():
            return candidate
    return None


def _format_timestamp(value: str | None) -> str:
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _receipt_rows() -> list[dict]:
    root = _existing_receipts_root()
    if root is None:
        return []

    rows = []
    for path in sorted(root.glob("*.json"), reverse=True):
        payload = _safe_json_load(path)
        if not payload:
            continue
        summary = payload.get("summary") or {}
        package = summary.get("package") or {}
        install = summary.get("install") or {}
        rows.append(
            {
                "kind": "receipt",
                "id": payload.get("receipt_id") or path.stem,
                "created_at": _format_timestamp(payload.get("created_at")),
                "decision": payload.get("decision"),
                "package": payload.get("package"),
                "package_version": payload.get("package_version"),
                "mode": payload.get("mode"),
                "requested_target": payload.get("requested_target"),
                "install_target": install.get("target"),
                "project_url": package.get("project_url"),
                "path": str(path),
                "raw": payload,
            }
        )
    return rows


def _bundle_rows() -> list[dict]:
    cache_root = get_cache_root()
    if not cache_root.exists():
        return []

    rows = []
    for entry_dir in sorted(cache_root.iterdir(), reverse=True):
        if not entry_dir.is_dir():
            continue
        if entry_dir.name in {"receipts", "provenance", "keys"}:
            continue

        metadata_path = entry_dir / "metadata.json"
        lock_path = entry_dir / "depshieldx-lock.txt"
        if not metadata_path.exists() or not lock_path.exists():
            continue

        payload = _safe_json_load(metadata_path)
        if not payload:
            continue

        rows.append(
            {
                "kind": "bundle",
                "id": entry_dir.name,
                "cached_at": _format_timestamp(payload.get("cached_at")),
                "success": payload.get("success"),
                "error_type": payload.get("error_type"),
                "backend": (payload.get("isolation") or {}).get("backend"),
                "downloaded_file_count": len(payload.get("downloaded_files") or []),
                "artifact_count": len(payload.get("artifact_hashes") or {}),
                "path": str(entry_dir),
                "raw": payload,
            }
        )
    return rows


def _provenance_rows() -> list[dict]:
    provenance_root = get_cache_root() / "provenance"
    if not provenance_root.exists():
        return []

    rows = []
    for path in sorted(provenance_root.glob("*.json"), reverse=True):
        payload = _safe_json_load(path)
        if not payload:
            continue
        result = payload.get("result") or {}
        signals = result.get("signals") or {}
        rows.append(
            {
                "kind": "provenance",
                "id": path.stem,
                "cached_at": _format_timestamp(payload.get("cached_at")),
                "package": result.get("package"),
                "package_version": result.get("version"),
                "block": bool(result.get("block")),
                "warning_count": len(result.get("warnings") or []),
                "info_count": len(result.get("infos") or []),
                "selected_file_count": signals.get("selected_file_count", 0),
                "attested_file_count": signals.get("attested_file_count", 0),
                "verified_attestation_count": signals.get("verified_attestation_count", 0),
                "path": str(path),
                "raw": payload,
            }
        )
    return rows


def build_ui_payload() -> dict:
    receipts = _receipt_rows()
    bundles = _bundle_rows()
    provenance = _provenance_rows()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "cache_root": str(get_cache_root()),
        "receipts": receipts,
        "bundles": bundles,
        "provenance": provenance,
        "summary": {
            "receipt_count": len(receipts),
            "bundle_count": len(bundles),
            "provenance_count": len(provenance),
        },
    }
