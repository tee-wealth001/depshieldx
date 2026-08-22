import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from depshieldx.cache import (
    CACHE_SCHEMA_VERSION,
    fingerprint_artifacts,
    load_cache_entry,
    prune_bundle_cache,
    prune_provenance_cache,
    store_cache_entry,
)
from depshieldx.sandbox import DownloadBundle


def _iso(age: timedelta) -> str:
    return (datetime.now(timezone.utc) - age).isoformat()


class CacheTests(unittest.TestCase):
    def test_fingerprint_artifacts_is_order_independent(self):
        left = fingerprint_artifacts({"a.whl": "111", "b.whl": "222"})
        right = fingerprint_artifacts({"b.whl": "222", "a.whl": "111"})

        self.assertEqual(left, right)

    def test_store_and_load_cache_entry_round_trip(self):
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as cache_dir:
            artifact = Path(temp_dir) / "Flask-3.1.3-py3-none-any.whl"
            artifact.write_bytes(b"wheel")
            lock = Path(temp_dir) / "depshieldx-lock.txt"
            lock.write_text("flask==3.1.3 --hash=sha256:abc\n")

            bundle = DownloadBundle(
                temp_dir=temp_dir,
                downloaded_files=[artifact.name],
                artifact_hashes={artifact.name: "abc"},
                requirements_path=str(lock),
                static_analysis={"blocked": False},
                fingerprint="fingerprint123",
            )

            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}):
                store_cache_entry(
                    bundle,
                    {"success": True, "error": None, "error_type": None, "evidence": {"pip_exit_code": 0}},
                )
                loaded = load_cache_entry("fingerprint123")

            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.metadata["cache_schema_version"], CACHE_SCHEMA_VERSION)
            self.assertEqual(loaded.metadata["downloaded_files"], [artifact.name])
            self.assertEqual(loaded.metadata["artifact_hashes"][artifact.name], "abc")

    def test_load_cache_entry_rejects_stale_schema(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            entry_dir = Path(cache_dir) / "stale-fingerprint"
            entry_dir.mkdir(parents=True, exist_ok=True)
            (entry_dir / "depshieldx-lock.txt").write_text("flask==3.1.3 --hash=sha256:abc\n")
            (entry_dir / "Flask-3.1.3-py3-none-any.whl").write_bytes(b"wheel")
            (entry_dir / "metadata.json").write_text(
                (
                    "{\n"
                    '  "downloaded_files": ["Flask-3.1.3-py3-none-any.whl"],\n'
                    '  "artifact_hashes": {"Flask-3.1.3-py3-none-any.whl": "abc"}\n'
                    "}\n"
                )
            )

            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}):
                loaded = load_cache_entry("stale-fingerprint")

            self.assertIsNone(loaded)


class PruneBundleCacheTests(unittest.TestCase):
    def _make_entry(self, cache_dir: str, name: str, cached_at: str) -> None:
        entry_dir = Path(cache_dir) / name
        entry_dir.mkdir(parents=True, exist_ok=True)
        (entry_dir / "depshieldx-lock.txt").write_text("flask==3.1.3\n")
        (entry_dir / "metadata.json").write_text(json.dumps({"cache_schema_version": CACHE_SCHEMA_VERSION, "cached_at": cached_at}))

    def test_removes_only_entries_older_than_max_age(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            self._make_entry(cache_dir, "old-entry", _iso(timedelta(days=40)))
            self._make_entry(cache_dir, "fresh-entry", _iso(timedelta(days=1)))

            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}):
                removed = prune_bundle_cache(max_age=timedelta(days=30))

            self.assertEqual(removed, ["old-entry"])
            self.assertFalse((Path(cache_dir) / "old-entry").exists())
            self.assertTrue((Path(cache_dir) / "fresh-entry").exists())

    def test_never_touches_receipts_provenance_keys_or_routing_dirs(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            for reserved in ("receipts", "provenance", "keys", "routing"):
                (Path(cache_dir) / reserved).mkdir()

            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}):
                removed = prune_bundle_cache(max_age=timedelta(days=0))

            self.assertEqual(removed, [])
            for reserved in ("receipts", "provenance", "keys", "routing"):
                self.assertTrue((Path(cache_dir) / reserved).exists())

    def test_leaves_entries_with_missing_or_malformed_metadata_alone(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            no_metadata_dir = Path(cache_dir) / "no-metadata"
            no_metadata_dir.mkdir()
            malformed_dir = Path(cache_dir) / "malformed-metadata"
            malformed_dir.mkdir()
            (malformed_dir / "metadata.json").write_text("not valid json{{{")

            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}):
                removed = prune_bundle_cache(max_age=timedelta(days=0))

            self.assertEqual(removed, [])
            self.assertTrue(no_metadata_dir.exists())
            self.assertTrue(malformed_dir.exists())

    def test_no_cache_root_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as parent_dir:
            missing_dir = str(Path(parent_dir) / "does-not-exist")
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": missing_dir}):
                self.assertEqual(prune_bundle_cache(), [])


class PruneProvenanceCacheTests(unittest.TestCase):
    def _make_provenance_file(self, cache_dir: str, key: str, cached_at: str) -> None:
        provenance_dir = Path(cache_dir) / "provenance"
        provenance_dir.mkdir(parents=True, exist_ok=True)
        (provenance_dir / f"{key}.json").write_text(json.dumps({"cache_version": 3, "cached_at": cached_at, "result": {}}))

    def test_removes_only_entries_past_the_24h_ttl(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            self._make_provenance_file(cache_dir, "stale-key", _iso(timedelta(hours=25)))
            self._make_provenance_file(cache_dir, "fresh-key", _iso(timedelta(hours=1)))

            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}):
                removed = prune_provenance_cache()

            self.assertEqual(removed, ["stale-key"])
            self.assertFalse((Path(cache_dir) / "provenance" / "stale-key.json").exists())
            self.assertTrue((Path(cache_dir) / "provenance" / "fresh-key.json").exists())

    def test_leaves_malformed_entries_alone(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            provenance_dir = Path(cache_dir) / "provenance"
            provenance_dir.mkdir(parents=True)
            (provenance_dir / "malformed.json").write_text("not valid json{{{")

            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}):
                removed = prune_provenance_cache()

            self.assertEqual(removed, [])
            self.assertTrue((provenance_dir / "malformed.json").exists())

    def test_no_provenance_dir_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as cache_dir:
            with patch.dict(os.environ, {"DEPSHIELDX_CACHE_DIR": cache_dir}):
                self.assertEqual(prune_provenance_cache(), [])
