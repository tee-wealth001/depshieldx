# Installation

Install the published package from PyPI:

```bash
python -m pip install depshieldx
```

If your machine has multiple Python versions, use a Python `3.11.4+` interpreter
explicitly:

```bash
python3.11 -m pip install depshieldx
```

## Standalone binaries

No Python runtime is required to run `depshieldx` itself this way.

Each [GitHub Release](https://github.com/tee-wealth001/depshieldx/releases) also
includes a standalone binary per platform (Windows x64, macOS x64/arm64, Linux x64)
built with PyInstaller. Download it, put it on `PATH`, and run it directly -- no
`pip install` and no separate Python interpreter needed just to launch `depshieldx`.

=== "macOS / Linux"

    Move the downloaded binary somewhere already on `PATH` and make it executable:

    ```bash
    chmod +x depshieldx-macos-arm64   # or depshieldx-linux-x64, depshieldx-macos-x64
    sudo mv depshieldx-macos-arm64 /usr/local/bin/depshieldx
    depshieldx --help
    ```

=== "Windows"

    Rename the download to `depshieldx.exe`, then add its folder to `PATH` (one time
    only). In PowerShell, replace `C:\tools\depshieldx` below with wherever you put the
    file:

    ```powershell
    [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\tools\depshieldx", "User")
    ```

    Close and reopen your terminal for the change to take effect, then run
    `depshieldx --help` to confirm it's found. Without a GUI/PowerShell, the same thing
    is done through *Settings -> System -> About -> Advanced system settings ->
    Environment Variables*, editing the `Path` entry under "User variables" to add the
    folder, then reopening any open terminal windows.

That said, `depshieldx` doesn't reimplement `pip` or `npm` -- it wraps the real
tools for actually resolving and installing packages, in either distribution:

- Using it against **PyPI** packages still requires a real Python + `pip` on the host,
  standalone binary or not. If the binary can't find one on `PATH`, it fails with a
  clear error rather than doing something unsafe.
- Using it against **npm/yarn/pnpm** packages only requires Node.js/`npm` on the host
  -- no Python needed at all, in either distribution.
- Using it against **Cargo/crates.io** packages only requires a Rust toolchain
  (`cargo`) on the host -- no Python needed at all, in either distribution.
- Using it against **Go modules** only requires a Go toolchain (`go`) on the host
  -- no Python needed at all, in either distribution.
- Using it against **Maven/Maven Central** packages only requires a Java + Maven
  toolchain (`mvn`) on the host -- no Python needed at all, in either
  distribution.
- Using it against **NuGet/NuGet.org** packages only requires a .NET SDK (`dotnet`) on
  the host -- no Python needed at all, in either distribution.
- Using it against **Pub/pub.dev** packages only requires a Dart SDK (`dart`) on the
  host -- no Python needed at all, in either distribution. Only the standalone
  Dart SDK is needed, not the full Flutter SDK.
- Using it against **RubyGems/rubygems.org** packages only requires Ruby with Bundler
  (`bundle`) on the host -- no Python needed at all, in either distribution.
  Bundler ships as a default gem on modern Ruby installs.
- Using it against **Composer/Packagist** packages only requires PHP with Composer
  (`composer`) on the host -- no Python needed at all, in either distribution.
- **Deep mode**, for any ecosystem, additionally requires Docker.

## Requirements

`depshieldx` is safest when the local runtime tools are current:

- Python `3.11.4` or newer
- `pip` `25.3` or newer
- Docker installed and running for `--deep`
- Trivy installed for the deeper container scan path

Install local development and release tooling with:

```bash
python -m pip install -e ".[dev]"
```

Run `depshieldx doctor` at any time to check every prerequisite -- the Python/pip
version gate, Docker daemon availability, host Trivy availability, and each
ecosystem's own toolchain on `PATH` -- in one pass, so a missing toolchain shows
up before an install/scan run rather than mid-run.

## Platform support

`depshieldx` works best where the local Python, `pip`, Docker, and browser integration
are set up cleanly.

- the local UI is localhost-only and uses the Python standard library browser/server
  stack, so it is the most platform-friendly part of the project
- the core fast scan and install flow is intended to be portable across macOS, Linux,
  and Windows
- routing creates a Windows batch shim on Windows and a shell shim on POSIX systems
- deep mode depends on Docker and Trivy, and some of the sandbox internals are still
  Unix-oriented

Windows support is improving, but macOS and Linux still have the broadest day-to-day
coverage in the codebase and docs.
