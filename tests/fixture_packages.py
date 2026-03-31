import textwrap
import zipfile
from pathlib import Path


def native_test_binary(*parts: bytes) -> bytes:
    return b"\x7fELF" + b"\x00" * 64 + b"\x00".join(parts)


def build_wheel(
    directory: str | Path,
    package_name: str,
    version: str = "1.0.0",
    package_files: dict[str, str | bytes] | None = None,
    dist_info_files: dict[str, str | bytes] | None = None,
) -> Path:
    target_dir = Path(directory)
    module_name = package_name.replace("-", "_")
    wheel_path = target_dir / f"{module_name}-{version}-py3-none-any.whl"
    dist_info_dir = f"{module_name}-{version}.dist-info"

    files: dict[str, str | bytes] = {
        f"{module_name}/__init__.py": f'__version__ = "{version}"\n',
        f"{dist_info_dir}/METADATA": textwrap.dedent(
            f"""\
            Metadata-Version: 2.1
            Name: {package_name}
            Version: {version}
            Summary: fixture package for integration tests
            """
        ).lstrip(),
        f"{dist_info_dir}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: depshieldx fixture builder\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
        f"{dist_info_dir}/top_level.txt": f"{module_name}\n",
    }
    if package_files:
        files.update(package_files)
    if dist_info_files:
        files.update({f"{dist_info_dir}/{name}": content for name, content in dist_info_files.items()})

    record_lines = [f"{path},," for path in sorted(files)]
    files[f"{dist_info_dir}/RECORD"] = "\n".join(record_lines + [f"{dist_info_dir}/RECORD,,"]) + "\n"

    with zipfile.ZipFile(wheel_path, "w") as archive:
        for path, content in files.items():
            if isinstance(content, bytes):
                archive.writestr(path, content)
            else:
                archive.writestr(path, content.encode("utf-8"))

    return wheel_path


def build_safe_wheel(directory: str | Path, package_name: str = "fixturepkg", version: str = "1.0.0") -> Path:
    module_name = package_name.replace("-", "_")
    return build_wheel(
        directory,
        package_name,
        version=version,
        package_files={
            f"{module_name}/core.py": (
                "def hello() -> str:\n"
                '    return "hello from fixture"\n'
            ),
        },
    )


def build_safe_native_wheel(
    directory: str | Path,
    package_name: str = "fixturenative",
    version: str = "1.0.0",
) -> Path:
    module_name = package_name.replace("-", "_")
    return build_wheel(
        directory,
        package_name,
        version=version,
        package_files={
            f"{module_name}/core.py": (
                "def hello() -> str:\n"
                '    return "hello from native fixture"\n'
            ),
            f"{module_name}/native.so": native_test_binary(
                b"PyInit_fixturenative",
                b"PyExc_ImportError",
                b"memcpy",
            ),
        },
    )


def build_malicious_native_wheel(
    directory: str | Path,
    package_name: str = "badfixture",
    version: str = "1.0.0",
) -> Path:
    module_name = package_name.replace("-", "_")
    return build_wheel(
        directory,
        package_name,
        version=version,
        package_files={
            f"{module_name}/native.so": native_test_binary(
                b"socket",
                b"connect",
                b"execve",
                b"/bin/sh",
                b"https://evil.example/payload",
            ),
        },
    )
