import json
import tempfile
import unittest

from depshieldx.ecosystems.composer.lockfiles import parse_composer_lock


class ParseComposerLockTests(unittest.TestCase):
    def _write_lockfile(self, payload: dict) -> str:
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".lock", delete=False)
        json.dump(payload, handle)
        handle.close()
        return handle.name

    def test_parses_real_hosted_entries(self):
        # Real shape confirmed directly against a real `composer require`
        # run during development.
        lockfile_path = self._write_lockfile(
            {
                "content-hash": "2a2a2a66d9508019bae038fec7606f5a",
                "packages": [
                    {
                        "name": "monolog/monolog",
                        "version": "3.10.0",
                        "source": {"type": "git", "url": "https://github.com/Seldaek/monolog.git", "reference": "b321dd6"},
                        "dist": {"type": "zip", "url": "https://api.github.com/repos/Seldaek/monolog/zipball/b321dd6", "reference": "b321dd6", "shasum": ""},
                    },
                    {
                        "name": "psr/log",
                        "version": "3.0.2",
                        "source": {"type": "git", "url": "https://github.com/php-fig/log.git", "reference": "f16e1d5"},
                        "dist": {"type": "zip", "url": "https://api.github.com/repos/php-fig/log/zipball/f16e1d5", "reference": "f16e1d5", "shasum": ""},
                    },
                ],
                "packages-dev": [],
                "platform": {"php": ">=8.1"},
                "platform-dev": {},
            }
        )

        resolved = parse_composer_lock(lockfile_path)

        self.assertEqual(resolved, {"monolog/monolog": "3.10.0", "psr/log": "3.0.2"})

    def test_includes_packages_dev(self):
        lockfile_path = self._write_lockfile(
            {
                "packages": [{"name": "monolog/monolog", "version": "3.10.0"}],
                "packages-dev": [{"name": "phpunit/phpunit", "version": "11.0.0"}],
            }
        )

        resolved = parse_composer_lock(lockfile_path)

        self.assertEqual(resolved, {"monolog/monolog": "3.10.0", "phpunit/phpunit": "11.0.0"})

    def test_platform_requirements_are_not_real_packages(self):
        # Confirmed directly: a real `php`/`ext-*` requirement in
        # composer.json lands in composer.lock's own "platform" object,
        # never in "packages"/"packages-dev" -- nothing for this parser
        # to skip explicitly, since it only ever reads those two arrays.
        lockfile_path = self._write_lockfile(
            {
                "packages": [{"name": "monolog/monolog", "version": "3.10.0"}],
                "packages-dev": [],
                "platform": {"php": ">=8.1", "ext-json": "*"},
                "platform-dev": {},
            }
        )

        resolved = parse_composer_lock(lockfile_path)

        self.assertEqual(resolved, {"monolog/monolog": "3.10.0"})
        self.assertNotIn("php", resolved)
        self.assertNotIn("ext-json", resolved)

    def test_empty_lockfile_returns_empty_dict(self):
        lockfile_path = self._write_lockfile({"packages": [], "packages-dev": []})

        resolved = parse_composer_lock(lockfile_path)

        self.assertEqual(resolved, {})


if __name__ == "__main__":
    unittest.main()
