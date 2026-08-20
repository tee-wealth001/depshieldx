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
from depshieldx.ecosystems.maven import MAVEN_ECOSYSTEM
from depshieldx.ecosystems.npm import NPM_ECOSYSTEM
from depshieldx.ecosystems.nuget import NUGET_ECOSYSTEM
from depshieldx.ecosystems.pub import PUB_ECOSYSTEM
from depshieldx.sandbox import (
    CARGO_SANDBOX_IMAGE_TAG,
    GO_SANDBOX_IMAGE_TAG,
    MAVEN_SANDBOX_IMAGE_TAG,
    NPM_SANDBOX_IMAGE_TAG,
    NUGET_SANDBOX_IMAGE_TAG,
    PUB_SANDBOX_IMAGE_TAG,
    REPORT_PREFIX,
    DownloadBundle,
    SandboxResult,
    TEXT_SUBPROCESS_KWARGS,
    _build_locked_requirements,
    _docker_daemon_available,
    _ensure_cargo_sandbox_image,
    _ensure_go_sandbox_image,
    _ensure_maven_sandbox_image,
    _ensure_npm_sandbox_image,
    _ensure_nuget_sandbox_image,
    _ensure_pub_sandbox_image,
    _extract_report,
    _run_command,
    _sandbox_cache_fingerprint,
    cleanup_download_bundle,
    prepare_cargo_download_bundle,
    prepare_download_bundle,
    prepare_go_download_bundle,
    prepare_maven_download_bundle,
    prepare_npm_download_bundle,
    prepare_nuget_download_bundle,
    prepare_pub_download_bundle,
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

        result = run_sandbox("flask", cache_enabled=False, require_docker=False)

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

    @patch("depshieldx.sandbox.prepare_download_bundle")
    @patch("depshieldx.sandbox._docker_daemon_available", return_value=(False, "docker offline"))
    def test_require_docker_defaults_to_true_not_a_silent_local_fallback(
        self,
        _mock_docker,
        mock_prepare_bundle,
    ):
        """require_docker used to default to False, so a caller who didn't
        think about it got the weaker local_subprocess backend (host-process
        execution, no real container isolation) silently by omission.
        Secure by default now: the same call without an explicit
        require_docker=False must behave exactly like require_docker=True."""
        result = run_sandbox("flask", cache_enabled=False)

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

    def test_prepare_cargo_download_bundle_rejects_path_traversal_in_malicious_crate(self):
        """A malicious (but real, checksum-consistent) crate could still ship a
        tar entry that resolves outside the vendor directory -- checksum
        verification only proves the bytes match what crates.io served, not
        that the tar entries themselves are safe. filter="data" must be
        applied unconditionally (no silent unfiltered fallback) so this
        raises instead of writing outside the temp vendor tree."""
        fake_ecosystem = unittest.mock.Mock()
        fake_ecosystem.selected_artifact_entries.return_value = [
            ("evil", "1.0.0", {"url": "https://static.crates.io/crates/evil/evil-1.0.0.crate"}),
        ]

        def fake_fetch(_artifact, destination):
            target = Path(destination) / "evil-1.0.0.crate"
            with tarfile.open(target, "w:gz") as archive:
                info = tarfile.TarInfo(name="../../evil.txt")
                data = b"pwned"
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            return target

        fake_ecosystem.fetch_artifact.side_effect = fake_fetch

        with self.assertRaises(tarfile.OutsideDestinationError):
            prepare_cargo_download_bundle(fake_ecosystem, {"evil": "1.0.0"})

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


class MavenSandboxTests(unittest.TestCase):
    _GSON_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.google.code.gson</groupId>
    <artifactId>gson-parent</artifactId>
    <version>2.11.0</version>
  </parent>
  <artifactId>gson</artifactId>
</project>
"""
    _GSON_PARENT_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.google.code.gson</groupId>
  <artifactId>gson-parent</artifactId>
  <version>2.11.0</version>
</project>
"""
    _COMMONS_LANG3_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-parent</artifactId>
    <version>73</version>
  </parent>
  <artifactId>commons-lang3</artifactId>
</project>
"""
    _COMMONS_PARENT_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-parent</artifactId>
  <version>73</version>
  <properties>
    <commons.junit.version>5.11.0</commons.junit.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.junit</groupId>
        <artifactId>junit-bom</artifactId>
        <version>${commons.junit.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""
    _JUNIT_BOM_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.junit</groupId>
  <artifactId>junit-bom</artifactId>
  <version>5.11.0</version>
</project>
"""

    def _fake_jar_bytes(self) -> bytes:
        # A real, minimal, openable zip archive -- analyze_artifacts()
        # opens every ".jar" as a real zip (jars are plain zip archives,
        # confirmed directly), so arbitrary non-zip bytes correctly raise
        # BadZipFile there rather than being silently accepted.
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        return buffer.getvalue()

    def _selected_entries(self, coordinate, version):
        group_id, _, artifact_id = coordinate.partition(":")
        artifact = {
            "url": f"https://repo1.maven.org/maven2/x/{artifact_id}-{version}.jar",
            "filename": f"{artifact_id}-{version}.jar",
            "checksum_algorithm": "sha256",
            "checksum": None,
        }
        return [(coordinate, version, artifact)]

    @patch("depshieldx.sandbox.fetch_pom_text")
    @patch.object(MAVEN_ECOSYSTEM, "fetch_artifact")
    @patch.object(MAVEN_ECOSYSTEM, "selected_artifact_entries")
    def test_prepare_maven_download_bundle_builds_m2_repo_layout_and_walks_parent_chain(
        self, mock_entries, mock_fetch_artifact, mock_fetch_pom
    ):
        coordinate, version = "com.google.code.gson:gson", "2.11.0"
        mock_entries.return_value = self._selected_entries(coordinate, version)

        def _fake_fetch_artifact(artifact, destination):
            path = Path(destination) / artifact["filename"]
            path.write_bytes(self._fake_jar_bytes())
            return path

        mock_fetch_artifact.side_effect = _fake_fetch_artifact

        def _fake_fetch_pom(group_id, artifact_id, pom_version):
            if artifact_id == "gson":
                return self._GSON_POM
            if artifact_id == "gson-parent":
                return self._GSON_PARENT_POM
            raise AssertionError(f"unexpected pom fetch: {group_id}:{artifact_id}:{pom_version}")

        mock_fetch_pom.side_effect = _fake_fetch_pom

        bundle = prepare_maven_download_bundle(MAVEN_ECOSYSTEM, {coordinate: version})
        try:
            self.assertIn("com.google.code.gson_gson-2.11.0.jar", bundle.downloaded_files)
            self.assertIn("pom.xml", bundle.downloaded_files)

            jar_path = Path(bundle.temp_dir) / "m2-repo" / "com" / "google" / "code" / "gson" / "gson" / "2.11.0" / "gson-2.11.0.jar"
            self.assertTrue(jar_path.exists())
            pom_path = jar_path.with_suffix(".pom")
            self.assertTrue(pom_path.exists())

            # Parent chain: gson's own pom references gson-parent, which
            # is never itself a resolved dependency -- confirmed directly
            # this fails Maven's dependency collector if missing.
            parent_pom_path = (
                Path(bundle.temp_dir) / "m2-repo" / "com" / "google" / "code" / "gson" / "gson-parent" / "2.11.0" / "gson-parent-2.11.0.pom"
            )
            self.assertTrue(parent_pom_path.exists())

            scratch_pom = (Path(bundle.temp_dir) / "pom.xml").read_text(encoding="utf-8")
            self.assertIn("<groupId>com.google.code.gson</groupId>", scratch_pom)
            self.assertIn("<artifactId>gson</artifactId>", scratch_pom)
            self.assertIn("<version>2.11.0</version>", scratch_pom)
        finally:
            cleanup_download_bundle(bundle)

    @patch("depshieldx.sandbox.fetch_pom_text")
    @patch.object(MAVEN_ECOSYSTEM, "fetch_artifact")
    @patch.object(MAVEN_ECOSYSTEM, "selected_artifact_entries")
    def test_prepare_maven_download_bundle_walks_bom_import_with_property_version(
        self, mock_entries, mock_fetch_artifact, mock_fetch_pom
    ):
        coordinate, version = "org.apache.commons:commons-lang3", "3.17.0"
        mock_entries.return_value = self._selected_entries(coordinate, version)

        def _fake_fetch_artifact(artifact, destination):
            path = Path(destination) / artifact["filename"]
            path.write_bytes(self._fake_jar_bytes())
            return path

        mock_fetch_artifact.side_effect = _fake_fetch_artifact

        def _fake_fetch_pom(group_id, artifact_id, pom_version):
            if artifact_id == "commons-lang3":
                return self._COMMONS_LANG3_POM
            if artifact_id == "commons-parent":
                return self._COMMONS_PARENT_POM
            if artifact_id == "junit-bom":
                return self._JUNIT_BOM_POM
            raise AssertionError(f"unexpected pom fetch: {group_id}:{artifact_id}:{pom_version}")

        mock_fetch_pom.side_effect = _fake_fetch_pom

        bundle = prepare_maven_download_bundle(MAVEN_ECOSYSTEM, {coordinate: version})
        try:
            # The BOM import's version is a "${commons.junit.version}"
            # placeholder in commons-parent's own pom, resolved against
            # that same pom's <properties> block (real, confirmed
            # directly for this exact example) -- not a literal "5.11.0"
            # anywhere in commons-lang3's or commons-parent's own text.
            bom_pom_path = (
                Path(bundle.temp_dir) / "m2-repo" / "org" / "junit" / "junit-bom" / "5.11.0" / "junit-bom-5.11.0.pom"
            )
            self.assertTrue(bom_pom_path.exists())
        finally:
            cleanup_download_bundle(bundle)

    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox.subprocess.run")
    def test_ensure_maven_sandbox_image_skips_build_when_image_present(self, mock_run, mock_run_command):
        mock_run.return_value = subprocess.CompletedProcess(args=["docker", "image", "inspect"], returncode=0)

        _ensure_maven_sandbox_image()

        mock_run_command.assert_not_called()

    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox.subprocess.run")
    def test_ensure_maven_sandbox_image_builds_when_image_missing(self, mock_run, mock_run_command):
        mock_run.return_value = subprocess.CompletedProcess(args=["docker", "image", "inspect"], returncode=1)

        _ensure_maven_sandbox_image()

        mock_run_command.assert_called_once()
        build_command = mock_run_command.call_args.args[0]
        self.assertEqual(build_command[:2], ["docker", "build"])
        self.assertIn(MAVEN_SANDBOX_IMAGE_TAG, build_command)
        self.assertIn("maven_sandbox.Dockerfile", " ".join(build_command))

    @patch("depshieldx.sandbox.subprocess.run")
    @patch("depshieldx.sandbox._scan_host_install_dir")
    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox._ensure_maven_sandbox_image")
    @patch("depshieldx.sandbox.prepare_maven_download_bundle")
    @patch("depshieldx.sandbox._docker_daemon_available", return_value=(True, None))
    def test_run_sandbox_uses_maven_image_and_maven_wrapper_for_maven_ecosystem(
        self,
        _mock_docker,
        mock_prepare_bundle,
        mock_ensure_image,
        mock_run_command,
        mock_scan_container,
        mock_subprocess_run,
    ):
        bundle = DownloadBundle(
            temp_dir="/tmp/maven-deep",
            downloaded_files=["com.google.code.gson_gson-2.11.0.jar", "pom.xml"],
            artifact_hashes={"com.google.code.gson_gson-2.11.0.jar": "abc"},
            requirements_path="/tmp/maven-deep/depshieldx-lock.txt",
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
            resolved_versions={"com.google.code.gson:gson": "2.11.0"},
            cache_enabled=False,
            require_docker=True,
            block_on_static_analysis=False,
            block_on_trivy=True,
            ecosystem=MAVEN_ECOSYSTEM,
        )

        self.assertTrue(result.success)
        mock_prepare_bundle.assert_called_once_with(MAVEN_ECOSYSTEM, {"com.google.code.gson:gson": "2.11.0"})
        mock_ensure_image.assert_called_once()
        docker_command = mock_run_command.call_args.args[0]
        self.assertIn(MAVEN_SANDBOX_IMAGE_TAG, docker_command)
        self.assertIn("sandbox_wrapper_maven.py", " ".join(docker_command))
        self.assertIn("python3", docker_command)
        self.assertIn("com.google.code.gson:gson@2.11.0", docker_command)
        self.assertIn(
            "/tmp/depshieldx-maven-work:rw,nosuid,nodev,exec,size=256m",
            docker_command,
        )

        # No new output needs to survive tmpfs teardown for Maven -- the
        # m2-repo/pom.xml layout was already built host-side, so Trivy
        # scans the bundle directory directly instead of the (unused,
        # empty) bind-mounted install dir.
        mock_scan_container.assert_called_once()
        scanned_dir = mock_scan_container.call_args.args[0]
        self.assertEqual(scanned_dir.replace("\\", "/"), "/tmp/maven-deep")
        self.assertIn(":/tmp/depshieldx-maven-unused:rw", " ".join(docker_command))


class NuGetSandboxTests(unittest.TestCase):
    def _selected_entries(self, package_id, version):
        artifact = {
            "url": f"https://api.nuget.org/v3-flatcontainer/x/{package_id}.{version}.nupkg",
            "filename": f"{package_id}.{version}.nupkg",
            "checksum_algorithm": "SHA512",
            "checksum": None,
        }
        return [(package_id, version, artifact)]

    def _fake_nupkg_bytes(self) -> bytes:
        # A real, minimal, openable zip archive -- analyze_artifacts()
        # opens every ".nupkg" as a real zip (nupkgs are plain zip
        # archives, confirmed directly), so arbitrary non-zip bytes
        # correctly raise BadZipFile there rather than being silently
        # accepted.
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("Newtonsoft.Json.nuspec", '<?xml version="1.0"?><package></package>')
        return buffer.getvalue()

    @patch("depshieldx.sandbox.subprocess.run")
    @patch("depshieldx.sandbox.resolve_dotnet_tool", return_value="/usr/local/bin/dotnet")
    @patch.object(NUGET_ECOSYSTEM, "fetch_artifact")
    @patch.object(NUGET_ECOSYSTEM, "selected_artifact_entries")
    def test_prepare_nuget_download_bundle_builds_flat_feed_and_scratch_csproj(
        self, mock_entries, mock_fetch_artifact, _mock_which, mock_subprocess_run
    ):
        package_id, version = "Newtonsoft.Json", "13.0.3"
        mock_entries.return_value = self._selected_entries(package_id, version)

        def _fake_fetch_artifact(artifact, destination):
            path = Path(destination) / artifact["filename"]
            path.write_bytes(self._fake_nupkg_bytes())
            return path

        mock_fetch_artifact.side_effect = _fake_fetch_artifact
        mock_subprocess_run.return_value = subprocess.CompletedProcess(
            args=["dotnet", "restore"], returncode=0, stdout="", stderr=""
        )

        bundle = prepare_nuget_download_bundle(NUGET_ECOSYSTEM, {package_id: version})
        try:
            self.assertIn("Newtonsoft.Json.13.0.3.nupkg", bundle.downloaded_files)
            self.assertIn("scratch.csproj", bundle.downloaded_files)
            self.assertIn("NuGet.Config", bundle.downloaded_files)

            csproj_text = (Path(bundle.temp_dir) / "scratch.csproj").read_text(encoding="utf-8")
            self.assertIn('Include="Newtonsoft.Json"', csproj_text)
            self.assertIn('Version="[13.0.3]"', csproj_text)

            config_text = (Path(bundle.temp_dir) / "NuGet.Config").read_text(encoding="utf-8")
            self.assertIn("<clear", config_text)
            self.assertIn("/tmp/packages", config_text)

            # The lock-file-generation restore runs BEFORE NuGet.Config is
            # written (so it isn't accidentally constrained to the local-
            # only source list meant for the sandboxed restore).
            restore_args = mock_subprocess_run.call_args.args[0]
            self.assertEqual(restore_args[0], "/usr/local/bin/dotnet")
            self.assertIn("restore", restore_args)
        finally:
            cleanup_download_bundle(bundle)

    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox.subprocess.run")
    def test_ensure_nuget_sandbox_image_skips_build_when_image_present(self, mock_run, mock_run_command):
        mock_run.return_value = subprocess.CompletedProcess(args=["docker", "image", "inspect"], returncode=0)

        _ensure_nuget_sandbox_image()

        mock_run_command.assert_not_called()

    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox.subprocess.run")
    def test_ensure_nuget_sandbox_image_builds_when_image_missing(self, mock_run, mock_run_command):
        mock_run.return_value = subprocess.CompletedProcess(args=["docker", "image", "inspect"], returncode=1)

        _ensure_nuget_sandbox_image()

        mock_run_command.assert_called_once()
        build_command = mock_run_command.call_args.args[0]
        self.assertEqual(build_command[:2], ["docker", "build"])
        self.assertIn(NUGET_SANDBOX_IMAGE_TAG, build_command)
        self.assertIn("nuget_sandbox.Dockerfile", " ".join(build_command))

    @patch("depshieldx.sandbox.subprocess.run")
    @patch("depshieldx.sandbox._scan_host_install_dir")
    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox._ensure_nuget_sandbox_image")
    @patch("depshieldx.sandbox.prepare_nuget_download_bundle")
    @patch("depshieldx.sandbox._docker_daemon_available", return_value=(True, None))
    def test_run_sandbox_uses_nuget_image_and_nuget_wrapper_for_nuget_ecosystem(
        self,
        _mock_docker,
        mock_prepare_bundle,
        mock_ensure_image,
        mock_run_command,
        mock_scan_container,
        mock_subprocess_run,
    ):
        bundle = DownloadBundle(
            temp_dir="/tmp/nuget-deep",
            downloaded_files=["Newtonsoft.Json.13.0.3.nupkg", "scratch.csproj", "NuGet.Config"],
            artifact_hashes={"Newtonsoft.Json.13.0.3.nupkg": "abc"},
            requirements_path="/tmp/nuget-deep/depshieldx-lock.txt",
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
            resolved_versions={"Newtonsoft.Json": "13.0.3"},
            cache_enabled=False,
            require_docker=True,
            block_on_static_analysis=False,
            block_on_trivy=True,
            ecosystem=NUGET_ECOSYSTEM,
        )

        self.assertTrue(result.success)
        mock_prepare_bundle.assert_called_once_with(NUGET_ECOSYSTEM, {"Newtonsoft.Json": "13.0.3"})
        mock_ensure_image.assert_called_once()
        docker_command = mock_run_command.call_args.args[0]
        self.assertIn(NUGET_SANDBOX_IMAGE_TAG, docker_command)
        self.assertIn("sandbox_wrapper_nuget.py", " ".join(docker_command))
        self.assertIn("python3", docker_command)
        self.assertIn("Newtonsoft.Json@13.0.3", docker_command)
        self.assertIn(
            "/tmp/depshieldx-nuget-work:rw,nosuid,nodev,exec,size=256m",
            docker_command,
        )

        # No new output needs to survive tmpfs teardown for NuGet -- the
        # flat .nupkg/scratch.csproj/NuGet.Config layout was already
        # built host-side, so Trivy scans the bundle directory directly
        # instead of the (unused, empty) bind-mounted install dir.
        mock_scan_container.assert_called_once()
        scanned_dir = mock_scan_container.call_args.args[0]
        self.assertEqual(scanned_dir.replace("\\", "/"), "/tmp/nuget-deep")
        self.assertIn(":/tmp/depshieldx-nuget-unused:rw", " ".join(docker_command))


class PubSandboxTests(unittest.TestCase):
    def _selected_entries(self, package_name, version):
        artifact = {
            "url": f"https://pub.dev/api/archives/{package_name}-{version}.tar.gz",
            "filename": f"{package_name}-{version}.tar.gz",
            "checksum_algorithm": "sha256",
            "checksum": None,
        }
        return [(package_name, version, artifact)]

    def _fake_archive_bytes(self) -> bytes:
        # A real, minimal, openable tar+gzip archive with no wrapping
        # top-level directory -- real pub.dev archives are plain
        # tar+gzip with files at the top level (confirmed directly), so
        # arbitrary non-tar bytes correctly raise a real extraction
        # error rather than being silently accepted.
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            data = b'name: http\nversion: "1.6.0"\n'
            info = tarfile.TarInfo(name="pubspec.yaml")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @patch("depshieldx.sandbox.subprocess.run")
    @patch("depshieldx.sandbox.resolve_dart_tool", return_value="/usr/local/bin/dart")
    @patch.object(PUB_ECOSYSTEM, "fetch_artifact")
    @patch.object(PUB_ECOSYSTEM, "selected_artifact_entries")
    def test_prepare_pub_download_bundle_builds_flat_archives_pub_cache_and_scratch_pubspec(
        self, mock_entries, mock_fetch_artifact, _mock_which, mock_subprocess_run
    ):
        package_name, version = "http", "1.6.0"
        mock_entries.return_value = self._selected_entries(package_name, version)

        def _fake_fetch_artifact(artifact, destination):
            path = Path(destination) / artifact["filename"]
            path.write_bytes(self._fake_archive_bytes())
            return path

        mock_fetch_artifact.side_effect = _fake_fetch_artifact
        mock_subprocess_run.return_value = subprocess.CompletedProcess(
            args=["dart", "pub", "get", "--offline"], returncode=0, stdout="", stderr=""
        )

        bundle = prepare_pub_download_bundle(PUB_ECOSYSTEM, {package_name: version})
        try:
            self.assertIn("http-1.6.0.tar.gz", bundle.downloaded_files)
            self.assertIn("pubspec.yaml", bundle.downloaded_files)

            pubspec_text = (Path(bundle.temp_dir) / "pubspec.yaml").read_text(encoding="utf-8")
            self.assertIn('http: "1.6.0"', pubspec_text)

            extracted_pubspec = Path(bundle.temp_dir) / "pub-cache" / "hosted" / "pub.dev" / "http-1.6.0" / "pubspec.yaml"
            self.assertTrue(extracted_pubspec.exists())

            resolve_args = mock_subprocess_run.call_args.args[0]
            self.assertEqual(resolve_args[0], "/usr/local/bin/dart")
            self.assertIn("--offline", resolve_args)
        finally:
            cleanup_download_bundle(bundle)

    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox.subprocess.run")
    def test_ensure_pub_sandbox_image_skips_build_when_image_present(self, mock_run, mock_run_command):
        mock_run.return_value = subprocess.CompletedProcess(args=["docker", "image", "inspect"], returncode=0)

        _ensure_pub_sandbox_image()

        mock_run_command.assert_not_called()

    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox.subprocess.run")
    def test_ensure_pub_sandbox_image_builds_when_image_missing(self, mock_run, mock_run_command):
        mock_run.return_value = subprocess.CompletedProcess(args=["docker", "image", "inspect"], returncode=1)

        _ensure_pub_sandbox_image()

        mock_run_command.assert_called_once()
        build_command = mock_run_command.call_args.args[0]
        self.assertEqual(build_command[:2], ["docker", "build"])
        self.assertIn(PUB_SANDBOX_IMAGE_TAG, build_command)
        self.assertIn("pub_sandbox.Dockerfile", " ".join(build_command))

    @patch("depshieldx.sandbox.subprocess.run")
    @patch("depshieldx.sandbox._scan_host_install_dir")
    @patch("depshieldx.sandbox._run_command")
    @patch("depshieldx.sandbox._ensure_pub_sandbox_image")
    @patch("depshieldx.sandbox.prepare_pub_download_bundle")
    @patch("depshieldx.sandbox._docker_daemon_available", return_value=(True, None))
    def test_run_sandbox_uses_pub_image_and_pub_wrapper_for_pub_ecosystem(
        self,
        _mock_docker,
        mock_prepare_bundle,
        mock_ensure_image,
        mock_run_command,
        mock_scan_container,
        mock_subprocess_run,
    ):
        bundle = DownloadBundle(
            temp_dir="/tmp/pub-deep",
            downloaded_files=["http-1.6.0.tar.gz", "pubspec.yaml", "pubspec.lock"],
            artifact_hashes={"http-1.6.0.tar.gz": "abc"},
            requirements_path="/tmp/pub-deep/depshieldx-lock.txt",
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
            resolved_versions={"http": "1.6.0"},
            cache_enabled=False,
            require_docker=True,
            block_on_static_analysis=False,
            block_on_trivy=True,
            ecosystem=PUB_ECOSYSTEM,
        )

        self.assertTrue(result.success)
        mock_prepare_bundle.assert_called_once_with(PUB_ECOSYSTEM, {"http": "1.6.0"})
        mock_ensure_image.assert_called_once()
        docker_command = mock_run_command.call_args.args[0]
        self.assertIn(PUB_SANDBOX_IMAGE_TAG, docker_command)
        self.assertIn("sandbox_wrapper_pub.py", " ".join(docker_command))
        self.assertIn("python3", docker_command)
        self.assertIn("http@1.6.0", docker_command)
        self.assertIn(
            "/tmp/depshieldx-pub-work:rw,nosuid,nodev,exec,size=256m",
            docker_command,
        )

        # No new output needs to survive tmpfs teardown for Pub -- the
        # flat .tar.gz/pubspec.yaml/pubspec.lock/pub-cache layout was
        # already built host-side, so Trivy scans the bundle directory
        # directly instead of the (unused, empty) bind-mounted install
        # dir.
        mock_scan_container.assert_called_once()
        scanned_dir = mock_scan_container.call_args.args[0]
        self.assertEqual(scanned_dir.replace("\\", "/"), "/tmp/pub-deep")
        self.assertIn(":/tmp/depshieldx-pub-unused:rw", " ".join(docker_command))


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
