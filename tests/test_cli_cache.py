import unittest
from datetime import timedelta
from unittest.mock import patch

from click.testing import CliRunner

from depshieldx.cli import cli
from depshieldx.storage.cache import BUNDLE_CACHE_DEFAULT_MAX_AGE_DAYS


class CacheCleanCommandTests(unittest.TestCase):
    def test_reports_counts_from_both_prune_functions(self):
        with patch("depshieldx.cli.commands.cache.prune_bundle_cache", return_value=["a", "b"]) as mock_bundles:
            with patch("depshieldx.cli.commands.cache.prune_provenance_cache", return_value=["x"]) as mock_provenance:
                result = CliRunner().invoke(cli, ["cache", "clean"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Removed 2 bundle cache entries.", result.output)
        self.assertIn("Removed 1 provenance cache entry.", result.output)
        mock_bundles.assert_called_once_with(max_age=timedelta(days=BUNDLE_CACHE_DEFAULT_MAX_AGE_DAYS))
        mock_provenance.assert_called_once_with()

    def test_bundle_max_age_days_option_is_passed_through(self):
        with patch("depshieldx.cli.commands.cache.prune_bundle_cache", return_value=[]) as mock_bundles:
            with patch("depshieldx.cli.commands.cache.prune_provenance_cache", return_value=[]):
                result = CliRunner().invoke(cli, ["cache", "clean", "--bundle-max-age-days", "7"])

        self.assertEqual(result.exit_code, 0)
        mock_bundles.assert_called_once_with(max_age=timedelta(days=7))

    def test_zero_removed_uses_singular_grammar_correctly(self):
        with patch("depshieldx.cli.commands.cache.prune_bundle_cache", return_value=[]):
            with patch("depshieldx.cli.commands.cache.prune_provenance_cache", return_value=[]):
                result = CliRunner().invoke(cli, ["cache", "clean"])

        self.assertIn("Removed 0 bundle cache entries.", result.output)
        self.assertIn("Removed 0 provenance cache entries.", result.output)


if __name__ == "__main__":
    unittest.main()
