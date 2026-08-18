import io
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import zipfile

from depshieldx.cache import CacheEntry
from depshieldx.ecosystems.cargo import CARGO_ECOSYSTEM
from depshieldx.ecosystems.go import GO_ECOSYSTEM
from depshieldx.ecosystems.npm import NPM_ECOSYSTEM
from depshieldx.sandbox import (
    CARGO_SANDBOX_IMAGE_TAG,
    GO_SANDBOX_IMAGE_TAG,
    NPM_SANDBOX_IMAGE_TAG,
    REPORT_PREFIX,
    DownloadBundle,
    SandboxResult,
    TEXT_SUBPROCESS_KWARGS,
    _build_locked_requirements,
    _docker_daemon_available,
    _ensure_cargo_sandbox_image,
    _ensure_go_sandbox_image,
    _ensure_npm_sandbox_image,
    _extract_report,
    _run_command,
    _sandbox_cache_fingerprint,
    cleanup_download_bundle,
    prepare_cargo_download_bundle,
    prepare_download_bundle,
    prepare_go_download_bundle,
    prepare_npm_download_bundle,
    run_sandbox,
)
from depshieldx.security.sandbox.sandbox_wrapper import EvidenceCollector, _create_target_dir, _discover_import_targets, _is_allowed_write_path


class SandboxHelpersTests(unittest.TestCase):
    def test_extract_report_reads_prefixed_json_line(self):
        output = "\n".join(
            [
                "some output",
                REPORT_PREFIX + '{"pip_exit_code": 0, "suspicious": false}',
                "tail output",
            ]
        )

        report = _extract_report(output)

        self.assertEqual(report, {"pip_exit_code": 0, "suspicious": False})

    @patch("depshieldx.sandbox._run_local_sandbox")
    @patch("depshieldx.sandbox.prepare_download_bundle")
    @patch("depshieldx.sandbox._docker_daemon_available", return_value=(False, "docker offline"))
    def test_run_sandbox_falls_back_to_local_backend_when_docker_missing(
        self,
        _mock_docker,
        mock_prepare_bundle,
        mock_run_local,
    ):
        bundle = DownloadBundle(
            temp_dir="/tmp/fallback",
            downloaded_files=["Flask-3.1.3.whl"],
            artifact_hashes={"Flask-3.1.3.whl": "abc"},
            requirements_path="/tmp/fallback/depshieldx-lock.txt",
            static_analysis={"blocked": False},
            fingerprint="fingerprint123",
        )
        mock_prepare_bundle.return_value = bundle
        mock_run_local.return_value = subprocess.CompletedProcess(
            args=["python", "sandbox_wrapper.py"],
            returncode=0,
            stdout=REPORT_PREFIX + '{"pip_exit_code": 0, "suspicious": false}',
            stderr="",
        )

        result = run_sandbox("flask", cache_enabled=False)

        self.assertTrue(result.success)
        self.assertEqual(result.error, None)
        self.assertEqual(result.error_type, None)
        self.assertEqual(result.isolation["backend"], "local_subprocess")
        self.assertEqual(result.evidence, {"pip_exit_code": 0, "suspicious": False})
        mock_run_local.assert_called_once()

    @patch("depshieldx.sandbox.analyze_artifacts", return_value={"blocked": False})
    @patch("depshieldx.sandbox.download_packages_local")
    def test_prepare_download_bundle_uses_host_download_for_local_fallback(self, mock_download_local, _mock_analyze):
        def fake_download(_targets, temp_dir, verbose=False):
            Path(temp_dir, "Flask-3.1.3-py3-none-any.whl").write_bytes(b"wheel-bytes")

        mock_download_local.side_effect = fake_download

        bundle = prepare_download_bundle(
            ["Flask==3.1.3"],
            resolved_versions={"Flask": "3.1.3"},
            download_via_host=True,
        )

        self.assertIn("Flask-3.1.3-py3-none-any.whl", bundle.downloaded_files)
        mock_download_local.assert_called_once()
        cleanup_download_bundle(bundle)

    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox.analyze_artifacts")
    @patch("depshieldx.sandbox.download_packages")
    @patch("depshieldx.sandbox._docker_daemon_available", return_value=(True, None))
    def test_run_sandbox_blocks_on_static_analysis(
        self,
        _mock_docker,
        mock_download,
        mock_analyze,
        mock_run_command,
    ):
        def fake_download(_package_name, temp_dir, verbose=False):
            Path(temp_dir, "pkg-0.1.0.tar.gz").write_bytes(b"fake")

        mock_download.side_effect = fake_download
        mock_analyze.return_value = {
            "artifacts_scanned": ["pkg-0.1.0.tar.gz"],
            "finding_count": 1,
            "high_count": 1,
            "medium_count": 0,
            "blocked": True,
            "findings": [
                {
                    "severity": "high",
                    "code": "install_network_access",
                    "artifact": "pkg-0.1.0.tar.gz",
                    "file": "setup.py",
                    "message": "Install script appears to perform network access.",
                }
            ],
        }

        result = run_sandbox("badpkg")

        self.assertFalse(result.success)
        self.assertEqual(result.error_type, "static_analysis")
        self.assertEqual(result.static_analysis["high_count"], 1)
        mock_run_command.assert_not_called()

    @patch("depshieldx.sandbox.prepare_download_bundle")
    @patch("depshieldx.sandbox._docker_daemon_available", return_value=(False, "docker offline"))
    def test_run_sandbox_can_require_docker(
        self,
        _mock_docker,
        mock_prepare_bundle,
    ):
        result = run_sandbox("flask", cache_enabled=False, require_docker=True)

        self.assertFalse(result.success)
        self.assertEqual(result.error_type, "environment")
        self.assertEqual(result.isolation["backend"], "docker")
        mock_prepare_bundle.assert_not_called()

    @patch("depshieldx.sandbox.subprocess.run")
    @patch("depshieldx.sandbox._scan_host_install_dir")
    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox.prepare_download_bundle")
    @patch("depshieldx.sandbox._docker_daemon_available", return_value=(True, None))
    def test_run_sandbox_can_block_on_trivy(
        self,
        _mock_docker,
        mock_prepare_bundle,
        mock_run_command,
        mock_scan_container,
        mock_subprocess_run,
    ):
        bundle = DownloadBundle(
            temp_dir="/tmp/deep",
            downloaded_files=["Flask-3.1.3.whl"],
            artifact_hashes={"Flask-3.1.3.whl": "abc"},
            requirements_path="/tmp/deep/depshieldx-lock.txt",
            static_analysis={"blocked": True, "high_count": 1, "findings": [{"code": "install_subprocess"}]},
            fingerprint="fingerprint123",
        )
        mock_prepare_bundle.return_value = bundle
        mock_run_command.return_value = subprocess.CompletedProcess(
            args=["docker", "run"],
            returncode=0,
            stdout=REPORT_PREFIX + '{"pip_exit_code": 0, "suspicious": false}',
            stderr="",
        )
        mock_scan_container.return_value = {
            "should_block": True,
            "vulnerabilities": [{"id": "CVE-2026-1234", "severity": "HIGH"}],
            "warnings": [],
            "scanned": True,
        }
        mock_subprocess_run.return_value = subprocess.CompletedProcess(
            args=["docker", "rm"],
            returncode=0,
            stdout="",
            stderr="",
        )

        result = run_sandbox(
            "flask",
            cache_enabled=False,
            require_docker=True,
            block_on_static_analysis=False,
            block_on_trivy=True,
        )

        self.assertFalse(result.success)
        self.assertEqual(result.error_type, "trivy")
        self.assertEqual(result.trivy_results["vulnerabilities"][0]["id"], "CVE-2026-1234")

    @patch("depshieldx.sandbox.load_cache_entry")
    @patch("depshieldx.sandbox.prepare_download_bundle")
    @patch("depshieldx.sandbox._docker_daemon_available", return_value=(True, None))
    def test_run_sandbox_reuses_cached_bundle(
        self,
        _mock_docker,
        mock_prepare_bundle,
        mock_load_cache,
    ):
        fresh_bundle = DownloadBundle(
            temp_dir="/tmp/fresh",
            downloaded_files=["Flask-3.1.3.whl"],
            artifact_hashes={"Flask-3.1.3.whl": "abc"},
            requirements_path="/tmp/fresh/depshieldx-lock.txt",
            static_analysis={"blocked": False},
            fingerprint="fingerprint123",
        )
        mock_prepare_bundle.return_value = fresh_bundle
        mock_load_cache.return_value = CacheEntry(
            fingerprint="fingerprint123",
            path="/tmp/cache/fingerprint123",
            metadata={
                "downloaded_files": ["Flask-3.1.3.whl"],
                "artifact_hashes": {"Flask-3.1.3.whl": "abc"},
                "static_analysis": {"blocked": False},
                "success": True,
                "error": None,
                "error_type": None,
                "evidence": {"pip_exit_code": 0, "suspicious": False},
            },
        )

        result = run_sandbox("flask", keep_bundle=True, cache_enabled=True)

        self.assertTrue(result.success)
        self.assertEqual(result.cache, {"hit": True, "fingerprint": "fingerprint123"})
        self.assertEqual(result.bundle.temp_dir, "/tmp/cache/fingerprint123")

    def test_build_locked_requirements_creates_hash_pinned_entries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            wheel = Path(temp_dir) / "Flask-3.1.3-py3-none-any.whl"
            wheel.write_bytes(b"wheel-bytes")

            requirements_path, artifact_hashes = _build_locked_requirements(
                temp_dir,
                {"Flask": "3.1.3"},
            )

            requirements_text = Path(requirements_path).read_text()

        self.assertIn("flask==3.1.3 --hash=sha256:", requirements_text)
        self.assertIn("Flask-3.1.3-py3-none-any.whl", artifact_hashes)

    @patch("depshieldx.sandbox.subprocess.run")
    def test_run_command_captures_output_by_default(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["pip", "download"],
            returncode=0,
            stdout="downloaded\n",
            stderr="",
        )

        result = _run_command(["pip", "download"])

        self.assertEqual(result.stdout, "downloaded\n")
        mock_run.assert_called_once_with(
            ["pip", "download"],
            check=True,
            capture_output=True,
            **TEXT_SUBPROCESS_KWARGS,
        )

    @patch("depshieldx.sandbox.subprocess.run")
    def test_docker_daemon_available_uses_tolerant_utf8_decoding(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["docker", "info"],
            returncode=0,
            stdout="Server:\n",
            stderr="",
        )

        available, detail = _docker_daemon_available()

        self.assertTrue(available)
        self.assertIsNone(detail)
        mock_run.assert_called_once_with(
            ["docker", "info"],
            check=True,
            capture_output=True,
            **TEXT_SUBPROCESS_KWARGS,
        )


class NpmSandboxTests(unittest.TestCase):
    def test_prepare_npm_download_bundle_fetches_and_hashes_artifacts(self):
        fake_ecosystem = unittest.mock.Mock()
        fake_ecosystem.selected_artifact_entries.return_value = [
            ("left-pad", "1.3.0", {"url": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}),
        ]

        def fake_fetch(_artifact, destination):
            target = Path(destination) / "left-pad-1.3.0.tgz"
            with tarfile.open(target, "w:gz") as archive:
                info = tarfile.TarInfo(name="package/index.js")
                data = b"module.exports = {};\n"
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            return target

        fake_ecosystem.fetch_artifact.side_effect = fake_fetch

        bundle = prepare_npm_download_bundle(fake_ecosystem, {"left-pad": "1.3.0"})
        try:
            self.assertIn("left-pad-1.3.0.tgz", bundle.downloaded_files)
            self.assertIn("left-pad-1.3.0.tgz", bundle.artifact_hashes)
            self.assertIn("left-pad@1.3.0", Path(bundle.requirements_path).read_text())
        finally:
            cleanup_download_bundle(bundle)

    def test_sandbox_cache_fingerprint_varies_by_ecosystem(self):
        pypi_fingerprint = _sandbox_cache_fingerprint({"a.whl": "abc"}, "docker", ecosystem="pypi")
        npm_fingerprint = _sandbox_cache_fingerprint({"a.whl": "abc"}, "docker", ecosystem="npm")

        self.assertNotEqual(pypi_fingerprint, npm_fingerprint)

    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox.subprocess.run")
    def test_ensure_npm_sandbox_image_skips_build_when_image_present(self, mock_run, mock_run_command):
        mock_run.return_value = subprocess.CompletedProcess(args=["docker", "image", "inspect"], returncode=0)

        _ensure_npm_sandbox_image()

        mock_run_command.assert_not_called()

    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox.subprocess.run")
    def test_ensure_npm_sandbox_image_builds_when_image_missing(self, mock_run, mock_run_command):
        mock_run.return_value = subprocess.CompletedProcess(args=["docker", "image", "inspect"], returncode=1)

        _ensure_npm_sandbox_image()

        mock_run_command.assert_called_once()
        build_command = mock_run_command.call_args.args[0]
        self.assertEqual(build_command[:2], ["docker", "build"])
        self.assertIn(NPM_SANDBOX_IMAGE_TAG, build_command)
        self.assertIn("npm_sandbox.Dockerfile", " ".join(build_command))

    @patch("depshieldx.sandbox.subprocess.run")
    @patch("depshieldx.sandbox._scan_host_install_dir")
    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox._ensure_npm_sandbox_image")
    @patch("depshieldx.sandbox.prepare_npm_download_bundle")
    @patch("depshieldx.sandbox._docker_daemon_available", return_value=(True, None))
    def test_run_sandbox_uses_node_image_and_npm_wrapper_for_npm_ecosystem(
        self,
        _mock_docker,
        mock_prepare_bundle,
        mock_ensure_image,
        mock_run_command,
        mock_scan_container,
        mock_subprocess_run,
    ):
        bundle = DownloadBundle(
            temp_dir="/tmp/npm-deep",
            downloaded_files=["left-pad-1.3.0.tgz"],
            artifact_hashes={"left-pad-1.3.0.tgz": "abc"},
            requirements_path="/tmp/npm-deep/depshieldx-lock.txt",
            static_analysis={"blocked": False},
            fingerprint="fingerprint123",
        )
        mock_prepare_bundle.return_value = bundle
        mock_run_command.return_value = subprocess.CompletedProcess(
            args=["docker", "run"],
            returncode=0,
            stdout=REPORT_PREFIX + '{"install_exit_code": 0, "suspicious": false}',
            stderr="",
        )
        mock_scan_container.return_value = {"scanned": True, "should_block": False}
        mock_subprocess_run.return_value = subprocess.CompletedProcess(
            args=["docker", "rm"], returncode=0, stdout="", stderr=""
        )

        result = run_sandbox(
            [],
            resolved_versions={"left-pad": "1.3.0"},
            cache_enabled=False,
            require_docker=True,
            block_on_static_analysis=False,
            block_on_trivy=True,
            ecosystem=NPM_ECOSYSTEM,
        )

        self.assertTrue(result.success)
        mock_prepare_bundle.assert_called_once_with(NPM_ECOSYSTEM, {"left-pad": "1.3.0"})
        mock_ensure_image.assert_called_once()
        docker_command = mock_run_command.call_args.args[0]
        self.assertIn(NPM_SANDBOX_IMAGE_TAG, docker_command)
        self.assertIn("sandbox_wrapper_npm.js", " ".join(docker_command))
        self.assertIn("HOME=/tmp", docker_command)
        # No extra capabilities beyond the base --cap-drop ALL posture:
        # strace only traces its own child process tree here, which needs
        # no added capability -- verified directly against a real container.
        self.assertNotIn("--cap-add", docker_command)
        mock_scan_container.assert_called_once()
        scanned_dir = mock_scan_container.call_args.args[0]
        self.assertTrue(scanned_dir.replace("\\", "/").endswith("/node_modules"))
        host_install_dir = scanned_dir.rsplit("node_modules", 1)[0].rstrip("/\\")
        self.assertIn(
            f"{host_install_dir}:/tmp/depshieldx-npm-install:rw",
            docker_command,
        )


class CargoSandboxTests(unittest.TestCase):
    def test_prepare_cargo_download_bundle_vendors_and_hashes_crates(self):
        fake_ecosystem = unittest.mock.Mock()
        fake_ecosystem.selected_artifact_entries.return_value = [
            ("serde", "1.0.219", {"url": "https://static.crates.io/crates/serde/serde-1.0.219.crate"}),
        ]

        def fake_fetch(_artifact, destination):
            target = Path(destination) / "serde-1.0.219.crate"
            with tarfile.open(target, "w:gz") as archive:
                # Real .crate tarballs nest everything under one top-level
                # "<name>-<version>/" directory -- reproduced here so the
                # flattening logic in prepare_cargo_download_bundle is
                # actually exercised, not just assumed to run.
                info = tarfile.TarInfo(name="serde-1.0.219/src/lib.rs")
                data = b"// serde\n"
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            return target

        fake_ecosystem.fetch_artifact.side_effect = fake_fetch

        bundle = prepare_cargo_download_bundle(fake_ecosystem, {"serde": "1.0.219"})
        try:
            self.assertIn("serde-1.0.219.crate", bundle.downloaded_files)
            self.assertIn("serde-1.0.219.crate", bundle.artifact_hashes)
            self.assertIn("serde@1.0.219", Path(bundle.requirements_path).read_text())

            vendor_entry = Path(bundle.temp_dir) / "vendor" / "serde-1.0.219"
            # Flattened: src/lib.rs directly under the vendor entry, not
            # double-nested under another serde-1.0.219/ directory.
            self.assertTrue((vendor_entry / "src" / "lib.rs").exists())
            self.assertTrue((vendor_entry / ".cargo-checksum.json").exists())
        finally:
            cleanup_download_bundle(bundle)

    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox.subprocess.run")
    def test_ensure_cargo_sandbox_image_skips_build_when_image_present(self, mock_run, mock_run_command):
        mock_run.return_value = subprocess.CompletedProcess(args=["docker", "image", "inspect"], returncode=0)

        _ensure_cargo_sandbox_image()

        mock_run_command.assert_not_called()

    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox.subprocess.run")
    def test_ensure_cargo_sandbox_image_builds_when_image_missing(self, mock_run, mock_run_command):
        mock_run.return_value = subprocess.CompletedProcess(args=["docker", "image", "inspect"], returncode=1)

        _ensure_cargo_sandbox_image()

        mock_run_command.assert_called_once()
        build_command = mock_run_command.call_args.args[0]
        self.assertEqual(build_command[:2], ["docker", "build"])
        self.assertIn(CARGO_SANDBOX_IMAGE_TAG, build_command)
        self.assertIn("cargo_sandbox.Dockerfile", " ".join(build_command))

    @patch("depshieldx.sandbox.subprocess.run")
    @patch("depshieldx.sandbox._scan_host_install_dir")
    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox._ensure_cargo_sandbox_image")
    @patch("depshieldx.sandbox.prepare_cargo_download_bundle")
    @patch("depshieldx.sandbox._docker_daemon_available", return_value=(True, None))
    def test_run_sandbox_uses_rust_image_and_cargo_wrapper_for_cargo_ecosystem(
        self,
        _mock_docker,
        mock_prepare_bundle,
        mock_ensure_image,
        mock_run_command,
        mock_scan_container,
        mock_subprocess_run,
    ):
        bundle = DownloadBundle(
            temp_dir="/tmp/cargo-deep",
            downloaded_files=["serde-1.0.219.crate"],
            artifact_hashes={"serde-1.0.219.crate": "abc"},
            requirements_path="/tmp/cargo-deep/depshieldx-lock.txt",
            static_analysis={"blocked": False},
            fingerprint="fingerprint123",
        )
        mock_prepare_bundle.return_value = bundle
        mock_run_command.return_value = subprocess.CompletedProcess(
            args=["docker", "run"],
            returncode=0,
            stdout=REPORT_PREFIX + '{"build_exit_code": 0, "suspicious": false}',
            stderr="",
        )
        mock_scan_container.return_value = {"scanned": True, "should_block": False}
        mock_subprocess_run.return_value = subprocess.CompletedProcess(
            args=["docker", "rm"], returncode=0, stdout="", stderr=""
        )

        result = run_sandbox(
            [],
            resolved_versions={"serde": "1.0.219"},
            cache_enabled=False,
            require_docker=True,
            block_on_static_analysis=False,
            block_on_trivy=True,
            ecosystem=CARGO_ECOSYSTEM,
        )

        self.assertTrue(result.success)
        mock_prepare_bundle.assert_called_once_with(CARGO_ECOSYSTEM, {"serde": "1.0.219"})
        mock_ensure_image.assert_called_once()
        docker_command = mock_run_command.call_args.args[0]
        self.assertIn(CARGO_SANDBOX_IMAGE_TAG, docker_command)
        self.assertIn("sandbox_wrapper_cargo.py", " ".join(docker_command))
        self.assertIn("python3", docker_command)
        self.assertIn("serde@=1.0.219", docker_command)
        self.assertIn("/tmp/packages/vendor", docker_command)
        # A real `cargo build` needs to execute what it just compiled out of
        # its own scratch project's target/ dir -- confirmed directly this
        # fails under the shared noexec /tmp, so the whole scratch project
        # dir gets its own exec-permitted tmpfs layered on top.
        self.assertIn(
            "/tmp/depshieldx-cargo-install:rw,nosuid,nodev,exec,size=256m",
            docker_command,
        )

        # No new output needs to survive tmpfs teardown for cargo -- the
        # vendor directory was already built host-side, so Trivy scans it
        # directly instead of the (unused, empty) bind-mounted install dir.
        mock_scan_container.assert_called_once()
        scanned_dir = mock_scan_container.call_args.args[0]
        self.assertEqual(scanned_dir.replace("\\", "/"), "/tmp/cargo-deep/vendor")
        self.assertIn(":/tmp/depshieldx-cargo-unused:rw", " ".join(docker_command))


class GoSandboxTests(unittest.TestCase):
    def _fake_module_zip(self, module: str, version: str) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(f"{module}@{version}/go.mod", f"module {module}\n\ngo 1.21\n")
            archive.writestr(f"{module}@{version}/errors.go", "package errors\n")
        return buffer.getvalue()

    @patch("depshieldx.sandbox.fetch_module_zip")
    @patch("depshieldx.sandbox.fetch_go_mod_text")
    @patch("depshieldx.sandbox.fetch_version_metadata")
    def test_prepare_go_download_bundle_builds_local_proxy_and_go_sum(
        self, mock_fetch_info, mock_fetch_mod, mock_fetch_zip
    ):
        module, version = "github.com/pkg/errors", "v0.9.1"
        mock_fetch_info.return_value = {"Version": version, "Time": "2020-01-14T19:47:44Z"}
        mock_fetch_mod.return_value = f"module {module}\n\ngo 1.13\n"
        mock_fetch_zip.return_value = self._fake_module_zip(module, version)

        bundle = prepare_go_download_bundle(GO_ECOSYSTEM, {module: version})
        try:
            self.assertIn(f"{module.replace('/', '_')}@{version}.zip", bundle.downloaded_files)
            self.assertIn("go.mod", bundle.downloaded_files)
            self.assertIn("go.sum", bundle.downloaded_files)

            go_mod_text = (Path(bundle.temp_dir) / "go.mod").read_text()
            self.assertIn(f"require {module} {version}", go_mod_text)

            go_sum_text = (Path(bundle.temp_dir) / "go.sum").read_text()
            self.assertIn(f"{module} {version} h1:", go_sum_text)
            self.assertIn(f"{module} {version}/go.mod h1:", go_sum_text)

            # Local file-based GOPROXY layout -- uppercase letters in the
            # module path must be "!"-escaped the same way the real network
            # proxy requires (confirmed directly for the network path;
            # both share the same underlying module-fetcher code).
            proxy_dir = Path(bundle.temp_dir) / "goproxy" / module / "@v"
            self.assertTrue((proxy_dir / f"{version}.info").exists())
            self.assertTrue((proxy_dir / f"{version}.mod").exists())
            self.assertTrue((proxy_dir / f"{version}.zip").exists())
            self.assertEqual((proxy_dir / "list").read_text().strip(), version)
        finally:
            cleanup_download_bundle(bundle)

    @patch("depshieldx.sandbox.fetch_module_zip")
    @patch("depshieldx.sandbox.fetch_go_mod_text")
    @patch("depshieldx.sandbox.fetch_version_metadata")
    def test_prepare_go_download_bundle_escapes_uppercase_module_path(
        self, mock_fetch_info, mock_fetch_mod, mock_fetch_zip
    ):
        module, version = "github.com/Masterminds/semver", "v1.5.0"
        mock_fetch_info.return_value = {"Version": version}
        mock_fetch_mod.return_value = f"module {module}\n\ngo 1.13\n"
        mock_fetch_zip.return_value = self._fake_module_zip(module, version)

        bundle = prepare_go_download_bundle(GO_ECOSYSTEM, {module: version})
        try:
            escaped_dir = Path(bundle.temp_dir) / "goproxy" / "github.com" / "!masterminds" / "semver" / "@v"
            self.assertTrue((escaped_dir / f"{version}.info").exists())
        finally:
            cleanup_download_bundle(bundle)

    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox.subprocess.run")
    def test_ensure_go_sandbox_image_skips_build_when_image_present(self, mock_run, mock_run_command):
        mock_run.return_value = subprocess.CompletedProcess(args=["docker", "image", "inspect"], returncode=0)

        _ensure_go_sandbox_image()

        mock_run_command.assert_not_called()

    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox.subprocess.run")
    def test_ensure_go_sandbox_image_builds_when_image_missing(self, mock_run, mock_run_command):
        mock_run.return_value = subprocess.CompletedProcess(args=["docker", "image", "inspect"], returncode=1)

        _ensure_go_sandbox_image()

        mock_run_command.assert_called_once()
        build_command = mock_run_command.call_args.args[0]
        self.assertEqual(build_command[:2], ["docker", "build"])
        self.assertIn(GO_SANDBOX_IMAGE_TAG, build_command)
        self.assertIn("go_sandbox.Dockerfile", " ".join(build_command))

    @patch("depshieldx.sandbox.subprocess.run")
    @patch("depshieldx.sandbox._scan_host_install_dir")
    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox._ensure_go_sandbox_image")
    @patch("depshieldx.sandbox.prepare_go_download_bundle")
    @patch("depshieldx.sandbox._docker_daemon_available", return_value=(True, None))
    def test_run_sandbox_uses_go_image_and_go_wrapper_for_go_ecosystem(
        self,
        _mock_docker,
        mock_prepare_bundle,
        mock_ensure_image,
        mock_run_command,
        mock_scan_container,
        mock_subprocess_run,
    ):
        bundle = DownloadBundle(
            temp_dir="/tmp/go-deep",
            downloaded_files=["github.com_pkg_errors@v0.9.1.zip", "go.mod", "go.sum"],
            artifact_hashes={"github.com_pkg_errors@v0.9.1.zip": "abc"},
            requirements_path="/tmp/go-deep/depshieldx-lock.txt",
            static_analysis={"blocked": False},
            fingerprint="fingerprint123",
        )
        mock_prepare_bundle.return_value = bundle
        mock_run_command.return_value = subprocess.CompletedProcess(
            args=["docker", "run"],
            returncode=0,
            stdout=REPORT_PREFIX + '{"download_exit_code": 0, "suspicious": false}',
            stderr="",
        )
        mock_scan_container.return_value = {"scanned": True, "should_block": False}
        mock_subprocess_run.return_value = subprocess.CompletedProcess(
            args=["docker", "rm"], returncode=0, stdout="", stderr=""
        )

        result = run_sandbox(
            [],
            resolved_versions={"github.com/pkg/errors": "v0.9.1"},
            cache_enabled=False,
            require_docker=True,
            block_on_static_analysis=False,
            block_on_trivy=True,
            ecosystem=GO_ECOSYSTEM,
        )

        self.assertTrue(result.success)
        mock_prepare_bundle.assert_called_once_with(GO_ECOSYSTEM, {"github.com/pkg/errors": "v0.9.1"})
        mock_ensure_image.assert_called_once()
        docker_command = mock_run_command.call_args.args[0]
        self.assertIn(GO_SANDBOX_IMAGE_TAG, docker_command)
        self.assertIn("sandbox_wrapper_go.py", " ".join(docker_command))
        self.assertIn("python3", docker_command)
        self.assertIn("github.com/pkg/errors@v0.9.1", docker_command)
        self.assertIn(
            "/tmp/depshieldx-go-work:rw,nosuid,nodev,exec,size=256m",
            docker_command,
        )

        # No new output needs to survive tmpfs teardown for Go -- go.mod/
        # go.sum were already built host-side, so Trivy scans the bundle
        # directory directly instead of the (unused, empty) bind-mounted
        # install dir.
        mock_scan_container.assert_called_once()
        scanned_dir = mock_scan_container.call_args.args[0]
        self.assertEqual(scanned_dir.replace("\\", "/"), "/tmp/go-deep")
        self.assertIn(":/tmp/depshieldx-go-unused:rw", " ".join(docker_command))


class EvidenceCollectorTests(unittest.TestCase):
    def test_create_target_dir_uses_platform_temp_root(self):
        target_dir = _create_target_dir()
        try:
            self.assertTrue(Path(target_dir).exists())
            self.assertIn(Path(tempfile.gettempdir()), Path(target_dir).parents)
        finally:
            Path(target_dir).rmdir()

    def test_create_target_dir_honors_sandbox_target_dir_override(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            override = str(Path(temp_dir) / "site-packages-sandbox")
            with patch.dict(os.environ, {"DEPSHIELDX_SANDBOX_TARGET_DIR": override}):
                target_dir = _create_target_dir()

            self.assertEqual(target_dir, override)
            self.assertTrue(Path(override).is_dir())

    def test_temp_root_probe_paths_are_allowed(self):
        # /private/tmp (macOS's real /tmp target) is intentionally not asserted here: it's only
        # covered via the dynamic realpath resolution of the actual runtime tempdir
        # (SYSTEM_TEMP_ROOT_PREFIXES), not the static TEMP_ROOT_PREFIXES tuple this helper checks
        # against directly.
        self.assertTrue(_is_allowed_write_path("/tmp/random-temp-probe"))
        self.assertTrue(_is_allowed_write_path("/var/tmp/random-temp-probe"))
        self.assertTrue(_is_allowed_write_path("/usr/tmp/random-temp-probe"))
        self.assertTrue(_is_allowed_write_path("/dev/null"))
        self.assertFalse(_is_allowed_write_path("/etc/random-temp-probe"))

    def test_evidence_collector_summarizes_writes_and_events(self):
        collector = EvidenceCollector()
        collector.add_event("write_attempt", {"path": "/tmp/pip-target-123/lib/python/pkg/a.py", "mode": "wb"})
        collector.add_event("write_attempt", {"path": "/tmp/pip-target-123/bin/tool", "mode": "wb"})
        collector.add_event("write_attempt", {"path": "/tmp/pip-target-123/lib/python/pkg/native.so", "mode": "wb"})
        collector.add_event("syscall:filesystem_mutation", {"call": "os.rename", "path": "/tmp/pip-target-123/lib/python/pkg/a.py"})
        collector.add_event("syscall:process_exec", {"call": "subprocess.Popen", "command": ["uname", "-rs"]})
        collector.add_event("subprocess_allowed", {"command": ["uname", "-rs"]})
        collector.add_event("import_ok", {"module": "flask"})
        collector.add_event("import_skipped", {"module": "markupsafe", "reason": "native_extension_distribution"})
        collector.add_event("import_failed", {"module": "badpkg", "type": "ImportError", "message": "boom"})
        collector.add_blocked("subprocess_denied", {"command": ["curl", "http://x"]})

        report = collector.report(1)

        self.assertEqual(report["write_count"], 3)
        self.assertEqual(
            report["write_samples"],
            [
                "/tmp/pip-target-123/lib/python/pkg/a.py",
                "/tmp/pip-target-123/bin/tool",
                "/tmp/pip-target-123/lib/python/pkg/native.so",
            ],
        )
        self.assertEqual(report["write_buckets"]["package_files"], 1)
        self.assertEqual(report["write_buckets"]["entrypoint_scripts"], 1)
        self.assertEqual(report["write_buckets"]["native_extensions"], 1)
        self.assertEqual(report["syscall_counts"]["filesystem_mutation"], 1)
        self.assertEqual(report["syscall_counts"]["process_exec"], 1)
        self.assertEqual(
            report["syscall_samples"][0],
            {
                "category": "syscall:filesystem_mutation",
                "detail": {"call": "os.rename", "path": "/tmp/pip-target-123/lib/python/pkg/a.py"},
            },
        )
        self.assertEqual(report["allowed_subprocesses"], [["uname", "-rs"]])
        self.assertEqual(report["imported_modules"], ["flask"])
        self.assertEqual(report["skipped_imports"], [{"module": "markupsafe", "reason": "native_extension_distribution"}])
        self.assertEqual(report["import_failures"][0]["module"], "badpkg")
        self.assertEqual(report["blocked_events"][0]["category"], "subprocess_denied")
        self.assertTrue(report["suspicious"])
        verdict_codes = [verdict["code"] for verdict in report["verdicts"]]
        self.assertIn("unexpected_subprocess_blocked", verdict_codes)
        self.assertIn("native_extensions_present", verdict_codes)
        self.assertIn("entrypoint_scripts_created", verdict_codes)
        self.assertIn("post_install_import_failures", verdict_codes)
        self.assertIn("post_install_import_checks_run", verdict_codes)
        self.assertIn("filesystem_mutations_traced", verdict_codes)

    def test_evidence_collector_treats_shared_library_mapping_failures_as_environmental(self):
        collector = EvidenceCollector()
        collector.add_event(
            "import_failed",
            {
                "module": "fastapi",
                "type": "ImportError",
                "message": "/tmp/site-packages-x/pydantic_core.so: failed to map segment from shared object",
            },
        )

        report = collector.report(0)

        self.assertEqual(len(report["risky_import_failures"]), 0)
        self.assertEqual(len(report["environmental_import_failures"]), 1)
        verdict_codes = [verdict["code"] for verdict in report["verdicts"]]
        self.assertNotIn("post_install_import_failures", verdict_codes)
        self.assertIn("post_install_import_environment_limitations", verdict_codes)

    def test_discover_import_targets_skips_native_distributions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            site_packages = Path(temp_dir)

            flask_dist = site_packages / "flask-3.1.3.dist-info"
            flask_dist.mkdir()
            (flask_dist / "top_level.txt").write_text("flask\n")
            (flask_dist / "RECORD").write_text("flask/__init__.py,,\n")

            markupsafe_dist = site_packages / "markupsafe-3.0.3.dist-info"
            markupsafe_dist.mkdir()
            (markupsafe_dist / "top_level.txt").write_text("markupsafe\n")
            (markupsafe_dist / "RECORD").write_text("markupsafe/_speedups.so,,\n")

            targets, skipped = _discover_import_targets(temp_dir, "Flask")

        self.assertEqual(targets, ["flask"])
        self.assertEqual(
            skipped,
            [{"module": "markupsafe", "reason": "native_extension_distribution"}],
        )
