import json
import tempfile
import unittest
from pathlib import Path

from depshieldx.ecosystems.nuget.lockfiles import parse_packages_lock


class ParsePackagesLockTests(unittest.TestCase):
    def _write_lockfile(self, payload: dict) -> str:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(payload, handle)
        handle.close()
        return handle.name

    def test_parses_real_single_framework_lockfile(self):
        lockfile_path = self._write_lockfile(
            {
                "version": 1,
                "dependencies": {
                    "net9.0": {
                        "Newtonsoft.Json": {
                            "type": "Direct",
                            "requested": "[13.0.3, 13.0.3]",
                            "resolved": "13.0.3",
                            "contentHash": "HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ==",
                        }
                    }
                },
            }
        )

        resolved = parse_packages_lock(lockfile_path)

        self.assertEqual(resolved, {"Newtonsoft.Json": "13.0.3"})

    def test_merges_multi_target_framework_sections(self):
        lockfile_path = self._write_lockfile(
            {
                "version": 1,
                "dependencies": {
                    "net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}},
                    "net9.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}},
                },
            }
        )

        resolved = parse_packages_lock(lockfile_path)

        self.assertEqual(resolved, {"Newtonsoft.Json": "13.0.3"})

    def test_keeps_newest_version_when_frameworks_disagree(self):
        lockfile_path = self._write_lockfile(
            {
                "version": 1,
                "dependencies": {
                    "net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"}},
                    "net9.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}},
                },
            }
        )

        resolved = parse_packages_lock(lockfile_path)

        self.assertEqual(resolved, {"Newtonsoft.Json": "13.0.3"})

    def test_includes_transitive_dependencies(self):
        lockfile_path = self._write_lockfile(
            {
                "version": 1,
                "dependencies": {
                    "net8.0": {
                        "Microsoft.IdentityModel.JsonWebTokens": {"type": "Direct", "resolved": "8.14.0"},
                        "Microsoft.IdentityModel.Tokens": {"type": "Transitive", "resolved": "8.14.0"},
                    }
                },
            }
        )

        resolved = parse_packages_lock(lockfile_path)

        self.assertEqual(
            resolved,
            {"Microsoft.IdentityModel.JsonWebTokens": "8.14.0", "Microsoft.IdentityModel.Tokens": "8.14.0"},
        )


if __name__ == "__main__":
    unittest.main()
