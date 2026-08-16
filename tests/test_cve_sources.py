import unittest

from depshieldx.intelligence.osv import OSV_ECOSYSTEM_NAMES


class OsvEcosystemNamesTests(unittest.TestCase):
    def test_pypi_maps_to_osv_pypi_identifier(self):
        # OSV's ecosystem enum is case-sensitive; confirmed against the real API.
        self.assertEqual(OSV_ECOSYSTEM_NAMES["pypi"], "PyPI")

    def test_npm_maps_to_osv_npm_identifier(self):
        self.assertEqual(OSV_ECOSYSTEM_NAMES["npm"], "npm")


if __name__ == "__main__":
    unittest.main()
