import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from depshieldx.cache import CACHE_SCHEMA_VERSION, fingerprint_artifacts, load_cache_entry, store_cache_entry
from depshieldx.sandbox import DownloadBundle


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
