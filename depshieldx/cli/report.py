"""Report-dict construction: the schema-versioned object every command builds
up and eventually hands to output.py to render/finish."""

from datetime import datetime, timezone

from ..ecosystems import PYPI_ECOSYSTEM, package_records
from ..storage.receipts import ReceiptUnavailableError, write_receipt

REPORT_SCHEMA_VERSION = "1"


def _build_report(package_name, mode, operation, ecosystem=PYPI_ECOSYSTEM):
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "ecosystem": ecosystem.name,
        "package": package_name,
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "operation": operation,
        "environment": {},
        "resolution": {},
        "provenance": None,
        "scan": None,
        "sandbox": None,
        "install": None,
    }


def _record_resolution(report, resolution):
    report["resolution"] = {
        "packages": resolution.packages,
        "install_target": resolution.install_target,
        "resolved_versions": resolution.resolved_versions,
        "selected_artifacts": resolution.selected_artifacts,
        "requested_targets": resolution.requested_targets,
        "source_type": resolution.source_type,
        "resolution_succeeded": resolution.resolution_succeeded,
        "resolution_error": resolution.resolution_error,
        "package_records": [record.__dict__ for record in package_records(report["ecosystem"], resolution)],
    }


def _prepare_report(report):
    return {key: value for key, value in dict(report).items() if not key.startswith("_")}


def _prepare_report_with_receipt(report):
    prepared = _prepare_report(report)
    if "receipt" not in prepared or not prepared["receipt"]:
        try:
            prepared["receipt"] = write_receipt(prepared)
        except ReceiptUnavailableError as exc:
            prepared["receipt"] = {
                "decision": "unavailable",
                "error": str(exc),
            }
    return prepared
