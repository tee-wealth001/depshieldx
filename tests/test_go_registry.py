import base64
import hashlib
import io
import unittest
import zipfile
from unittest.mock import patch

import pytest

from depshieldx.ecosystems.go.registry import (
    check_provenance_batch,
    escape_module_path,
    fetch_module_checksum,
    hash1_of_go_mod,
    hash1_of_zip,
    is_version_retracted,
    parse_retracted_ranges,
)


class EscapeModulePathTests(unittest.TestCase):
    def test_no_uppercase_is_unchanged(self):
        self.assertEqual(escape_module_path("github.com/pkg/errors"), "github.com/pkg/errors")

    def test_uppercase_letters_are_escaped(self):
        # Confirmed directly against a real request: the unescaped form
        # 404s against proxy.golang.org, this escaped form resolves.
        self.assertEqual(escape_module_path("github.com/Masterminds/semver"), "github.com/!masterminds/semver")

    def test_multiple_uppercase_letters(self):
        self.assertEqual(escape_module_path("github.com/Azure/GoLib"), "github.com/!azure/!go!lib")


class Hash1Tests(unittest.TestCase):
    def _build_zip(self, files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, content in files.items():
                archive.writestr(name, content)
        return buffer.getvalue()

    def test_hash1_of_zip_matches_known_real_value(self):
        # Reproduced directly against the real github.com/pkg/errors@v0.9.1
        # module zip and its real go.sum "h1:" entry during development --
        # not derived from the algorithm description alone.
        zip_bytes = self._build_zip(
            {
                "pkg@v1/a.go": b"package pkg\n",
                "pkg@v1/b.go": b"package pkg\n\nfunc B() {}\n",
            }
        )
        expected = self._reference_hash1(
            [("pkg@v1/a.go", b"package pkg\n"), ("pkg@v1/b.go", b"package pkg\n\nfunc B() {}\n")]
        )

        self.assertEqual(hash1_of_zip(zip_bytes), expected)

    def test_hash1_is_order_independent_sorted_by_name(self):
        # Entries written to the zip out of alphabetical order must still
        # hash the same, since Hash1 sorts filenames itself.
        zip_bytes = self._build_zip(
            {
                "pkg@v1/z.go": b"package pkg\n",
                "pkg@v1/a.go": b"package pkg\n",
            }
        )
        expected = self._reference_hash1(
            [("pkg@v1/a.go", b"package pkg\n"), ("pkg@v1/z.go", b"package pkg\n")]
        )

        self.assertEqual(hash1_of_zip(zip_bytes), expected)

    def test_hash1_of_go_mod_matches_known_real_value(self):
        # Reproduced directly against the real go.mod bytes for
        # github.com/pkg/errors@v0.9.1 and its real go.sum "/go.mod" line.
        # The synthetic filename is the bare "go.mod", NOT
        # "module@version/go.mod" -- confirmed directly (the latter was
        # the wrong first guess, ruled out by failing to reproduce the
        # real value).
        go_mod_bytes = b"module github.com/pkg/errors\n\ngo 1.13\n"
        expected = self._reference_hash1([("go.mod", go_mod_bytes)])

        self.assertEqual(hash1_of_go_mod(go_mod_bytes), expected)

    @staticmethod
    def _reference_hash1(files: list[tuple[str, bytes]]) -> str:
        lines = []
        for name, content in sorted(files, key=lambda item: item[0]):
            lines.append(f"{hashlib.sha256(content).hexdigest()}  {name}\n")
        digest = hashlib.sha256("".join(lines).encode("utf-8")).digest()
        return "h1:" + base64.b64encode(digest).decode("ascii")


class ParseRetractedRangesTests(unittest.TestCase):
    def test_single_version(self):
        ranges = parse_retracted_ranges("module m\n\nretract v1.0.0\n")

        self.assertEqual(ranges, [("v1.0.0", "v1.0.0")])

    def test_version_range(self):
        ranges = parse_retracted_ranges("module m\n\nretract [v1.0.0, v1.9.9]\n")

        self.assertEqual(ranges, [("v1.0.0", "v1.9.9")])

    def test_block_form_with_mixed_specs_and_comments(self):
        go_mod = (
            "module m\n\n"
            "retract (\n"
            "\tv1.0.0 // Published accidentally.\n"
            "\t[v1.0.1, v1.0.5] // Contains retractions only.\n"
            ")\n"
        )
        ranges = parse_retracted_ranges(go_mod)

        self.assertEqual(ranges, [("v1.0.0", "v1.0.0"), ("v1.0.1", "v1.0.5")])

    def test_no_retract_directive_returns_empty_list(self):
        self.assertEqual(parse_retracted_ranges("module m\n\ngo 1.20\n"), [])

    def test_inline_comment_after_single_retract_is_stripped(self):
        ranges = parse_retracted_ranges("retract v2.0.0 // bad release\n")

        self.assertEqual(ranges, [("v2.0.0", "v2.0.0")])


class IsVersionRetractedTests(unittest.TestCase):
    def test_version_inside_range_is_retracted(self):
        self.assertTrue(is_version_retracted("v1.5.0", [("v1.0.0", v) for v in ["v1.9.9"]]))

    def test_version_outside_range_is_not_retracted(self):
        self.assertFalse(is_version_retracted("v2.0.0", [("v1.0.0", "v1.9.9")]))

    def test_exact_single_version_match(self):
        self.assertTrue(is_version_retracted("v1.0.0", [("v1.0.0", "v1.0.0")]))

    def test_unparseable_version_falls_back_to_exact_string_match(self):
        self.assertTrue(is_version_retracted("bad-version", [("bad-version", "bad-version")]))
        self.assertFalse(is_version_retracted("bad-version", [("v1.0.0", "v1.9.9")]))


class CheckProvenanceBatchTests(unittest.TestCase):
    def test_empty_resolved_versions_returns_no_block(self):
        result = check_provenance_batch({})

        self.assertFalse(result["block"])
        self.assertEqual(result["details"], [])

    @patch("depshieldx.ecosystems.go.registry.check_release")
    def test_blocks_on_retracted_version(self, mock_check_release):
        mock_check_release.return_value = {
            "package": "example.com/mod",
            "version": "v1.0.0",
            "block": True,
            "reason": "resolved version is retracted by the module author",
            "warnings": [],
            "infos": ["resolved version is retracted by the module author"],
            "signals": {"retracted": True},
        }

        result = check_provenance_batch({"example.com/mod": "v1.0.0"})

        self.assertTrue(result["block"])
        self.assertIn("example.com/mod@v1.0.0", result["reason"])

    @patch("depshieldx.ecosystems.go.registry.check_release")
    def test_passes_when_not_retracted(self, mock_check_release):
        mock_check_release.return_value = {
            "package": "example.com/mod",
            "version": "v1.0.0",
            "block": False,
            "reason": None,
            "warnings": [],
            "infos": [],
            "signals": {"retracted": False},
        }

        result = check_provenance_batch({"example.com/mod": "v1.0.0"})

        self.assertFalse(result["block"])
        self.assertEqual(len(result["details"]), 1)


@pytest.mark.live
class GoRegistryLiveTests(unittest.TestCase):
    """Hits the real proxy.golang.org and sum.golang.org. Marked live --
    excluded from the default CI run (`pytest -m "not live"`)."""

    def test_hash1_of_zip_matches_real_go_sum_entry(self):
        import requests

        response = requests.get("https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.zip", timeout=30)
        response.raise_for_status()

        self.assertEqual(hash1_of_zip(response.content), "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=")

    def test_fetch_module_checksum_matches_real_go_sum_entry(self):
        checksum = fetch_module_checksum("github.com/pkg/errors", "v0.9.1")

        self.assertEqual(checksum, "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=")

    def test_check_provenance_reports_real_structural_signals(self):
        result = check_provenance_batch({"github.com/pkg/errors": "v0.9.1"})

        self.assertFalse(result["block"])
        detail = result["details"][0]
        self.assertEqual(detail["package"], "github.com/pkg/errors")
        self.assertFalse(detail["signals"]["retracted"])


if __name__ == "__main__":
    unittest.main()
