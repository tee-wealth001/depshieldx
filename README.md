# depshieldx

[![PyPI version](https://img.shields.io/pypi/v/depshieldx.svg)](https://pypi.org/project/depshieldx/)
[![Docs](https://img.shields.io/badge/docs-github%20pages-10b981)](https://tee-wealth001.github.io/depshieldx/)

`depshieldx` is a safer wrapper around package install and scan workflows, for PyPI (Python), npm/yarn/pnpm (JavaScript), Cargo/crates.io (Rust), Go modules, Maven/Maven Central (Java), and NuGet/NuGet.org (.NET) -- see [npm / yarn / pnpm Support](#npm--yarn--pnpm-support), [Cargo / crates.io Support](#cargo--cratesio-support), [Go Modules Support](#go-modules-support), [Maven / Maven Central Support](#maven--maven-central-support), and [NuGet Support](#nuget-support) for the ecosystem-specific details.

Before installing, it resolves the full package set, checks provenance for the exact artifacts that would be used, queries four vulnerability sources for the resolved versions, and can optionally run a deeper Docker + Trivy validation path with real behavioral tracing of the sandboxed install. Every completed install or scan also writes signed local receipt JSON files.

## Installation

Install the published package from PyPI:

```bash
python -m pip install depshieldx
```

If your machine has multiple Python versions, use a Python `3.11.4+` interpreter explicitly:

```bash
python3.11 -m pip install depshieldx
```

### Standalone binaries (no Python runtime required to run `depshieldx` itself)

Each [GitHub Release](https://github.com/tee-wealth001/depshieldx/releases) also includes a standalone binary per platform (Windows x64, macOS x64/arm64, Linux x64) built with PyInstaller. Download it, put it on `PATH`, and run it directly -- no `pip install` and no separate Python interpreter needed just to launch `depshieldx`.

That said, `depshieldx` doesn't reimplement `pip` or `npm` -- it wraps the real tools for actually resolving and installing packages, in either distribution:

- Using it against **PyPI** packages still requires a real Python + `pip` on the host, standalone binary or not. If the binary can't find one on `PATH`, it fails with a clear error rather than doing something unsafe.
- Using it against **npm/yarn/pnpm** packages only requires Node.js/`npm` on the host -- no Python needed at all, in either distribution.
- Using it against **Cargo/crates.io** packages only requires a Rust toolchain (`cargo`) on the host -- no Python needed at all, in either distribution.
- Using it against **Go modules** only requires a Go toolchain (`go`) on the host -- no Python needed at all, in either distribution.
- Using it against **Maven/Maven Central** packages only requires a Java + Maven toolchain (`mvn`) on the host -- no Python needed at all, in either distribution.
- Using it against **NuGet/NuGet.org** packages only requires a .NET SDK (`dotnet`) on the host -- no Python needed at all, in either distribution.
- **Deep mode**, for any ecosystem, additionally requires Docker.

Project links:

- PyPI: https://pypi.org/project/depshieldx/
- Docs: https://tee-wealth001.github.io/depshieldx/
- Source: https://github.com/tee-wealth001/depshieldx

## What It Does

- resolves the full dependency set before installation, for PyPI, npm/yarn/pnpm, Cargo/crates.io, Go modules, Maven/Maven Central, or NuGet/NuGet.org
- checks provenance for the selected release artifacts (PyPI attestations, or npm's SLSA provenance attestations -- both verified cryptographically via real Sigstore bundle verification, not just presence checks; crates.io and Go modules have no equivalent per-package attestation infrastructure, so Cargo and Go packages get structural checks instead -- yanked/retracted-release status, registry metadata -- rather than cryptographic verification. Go's checksums are still verified cryptographically, just transparently inside the `go` toolchain itself, not as a separate `depshieldx` step. Maven combines checksum + structural PGP-presence checks with real cryptographic Sigstore verification where a publisher has opted in, since January 2025. NuGet combines a real cryptographic checksum check against the registry's own published hash with structural repository-signature presence -- NuGet.org has no Sigstore equivalent, but it does unconditionally repository-sign every package with an X.509/Authenticode signature)
- queries 4 vulnerability sources for the resolved package versions:
  - OSV
  - GitHub Advisories
  - CISA KEV
  - deps.dev
- supports a deeper Docker + Trivy scan mode, plus real syscall-level behavioral tracing during sandboxed installs, for PyPI, npm/yarn/pnpm, Cargo/crates.io, Go modules, Maven/Maven Central, and NuGet/NuGet.org
- writes signed local receipts for installs and scans

## Quick Start

Install with the default path:

```bash
depshieldx install requests
```

Run the deeper validation path:

```bash
depshieldx install requests --deep
```

Scan without installing:

```bash
depshieldx scan requests
```

Scan a requirements file:

```bash
depshieldx scan -r requirements.txt
```

Install from `pyproject.toml`:

```bash
depshieldx install --pyproject pyproject.toml
```

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

## Platform Support

`depshieldx` works best where the local Python, `pip`, Docker, and browser integration are set up cleanly.

- the local UI is localhost-only and uses the Python standard library browser/server stack, so it is the most platform-friendly part of the project
- the core fast scan and install flow is intended to be portable across macOS, Linux, and Windows
- routing now creates a Windows batch shim on Windows and a shell shim on POSIX systems
- deep mode depends on Docker and Trivy, and some of the sandbox internals are still Unix-oriented

Windows support is improving, but macOS and Linux still have the broadest day-to-day coverage in the codebase and docs.

## Modes

`depshieldx` has two modes:

- `fast`
- `deep`

Plain `install` and plain `scan` default to `fast`.

`deep` is supported for PyPI, npm/yarn/pnpm, Cargo/crates.io, Go modules, Maven/Maven Central, and NuGet/NuGet.org input.

### Fast mode

Fast mode:

- resolves the exact package versions that would be installed
- checks provenance for the resolved package set
- queries OSV, GitHub Advisories, CISA KEV, and deps.dev
- blocks if any resolved package or dependency is reported as vulnerable by the blocking sources

Fast mode does not use Docker or Trivy.

### Deep mode

Deep mode does everything in fast mode first, then:

- installs the resolved package set in Docker
- runs Trivy on the sandboxed install result
- blocks if the Docker environment is unavailable or Trivy returns blocking findings

For `install --deep`, the host install only happens after the fast checks and the Docker + Trivy stage both pass.

`depshieldx` shells out to the local `pip` (or, for npm, the local `npm`; for Cargo, the local `cargo`; for Go, the local `go`; for Maven, the local `mvn`; for NuGet, the local `dotnet`) for resolution, download, and host install steps, so keeping those tools up to date is part of the security model.

For PyPI, deep mode also traces filesystem writes, subprocess launches, and network access in-process during the sandboxed install (via `sys.addaudithook`) and actively blocks disallowed ones in real time. For npm, which has no equivalent in-process hook, behavioral tracing instead wraps the sandboxed `npm install` in `strace`, observing the same categories of activity across the whole install (including lifecycle scripts) rather than blocking individual syscalls live -- filesystem/network isolation is still enforced by the container itself either way. The npm sandbox runs in a small `node:20` + `strace` image `depshieldx` builds and caches locally the first time it's needed.

Cargo/crates.io behavioral tracing works the same way as npm's: the sandboxed `cargo build --offline` runs wrapped in `strace`, observing filesystem, process, and network activity (including `build.rs` scripts and proc-macros) rather than blocking individual syscalls live. The Cargo sandbox runs in a small `rust:1-slim` + `strace` image built and cached locally the first time it's needed. One mechanical difference from npm/PyPI: since there's no new installed output that needs to survive the sandbox, Trivy scans a host-side vendor directory of the resolved `.crate` files (checksum-verified against crates.io) built before the container runs, rather than a bind-mounted install destination.

Go modules behavioral tracing works the same way: the sandboxed `go build` runs wrapped in `strace`, observing filesystem, process, and network activity (`init()` functions and `//go:generate`-produced code are Go's equivalent of Cargo's `build.rs`/proc-macros) rather than blocking individual syscalls live. The Go sandbox runs in a small `golang:1-bookworm` + `strace` image built and cached locally the first time it's needed. Like Cargo, Trivy scans a host-side `go.mod`/`go.sum` pair built before the container runs -- Trivy reads Go's manifest files natively, needing no extracted source tree the way Cargo's vendor directory does. One Go-specific wrinkle: unlike Cargo (which compiles every declared dependency regardless of use), Go only compiles what's actually imported, so a scratch program blank-imports every resolved module to force real compilation -- and not every module has an importable root package (some are subpackage-only, e.g. `golang.org/x/crypto`). Those are skipped from tracing rather than failing the whole build, and listed in the full JSON report's `skipped_modules`.

Maven behavioral tracing is different in one fundamental way: unlike Cargo's `build.rs` or Go's `init()`, a jar consumed as a plain Maven dependency has no code that runs automatically just by being resolved, or even sitting on the compile classpath. The one real exception is an annotation processor registered via `META-INF/services` (Lombok, MapStruct, Dagger, and similar) -- `javac` auto-discovers and invokes it during any compile it's present for, regardless of whether the compiled source actually uses its target annotations. So the sandboxed `mvn compile` (against a trivial scratch source file, wrapped in `strace`) traces real activity for that class of dependency, and genuinely zero extra activity for the (large majority) of ordinary libraries that register no processor -- an accurate verdict, not a coverage gap. The Maven sandbox runs in a small `maven:3-eclipse-temurin-21` + `strace` image built and cached locally the first time it's needed, with Maven's own default-lifecycle plugin set pre-warmed into the image at build time (a real, Maven-specific requirement: `compile` is itself a Maven plugin goal, needing dozens of plugin/dependency jars resolved before it can run at all, which the sandbox can't fetch once it's offline). Like Cargo/Go, Trivy scans a host-side scratch `pom.xml` built before the container runs, listing every resolved coordinate as a pinned direct dependency.

NuGet behavioral tracing has the broadest code-execution surface of the four compiled ecosystems: a `.nupkg` consumed as a plain `PackageReference` has no code that runs automatically during `dotnet restore` alone, but any package shipping a `build/*.targets` or `build/*.props` file gets it imported and evaluated during `dotnet build` -- not a narrow processor-registration mechanism like Maven's, but MSBuild's own general build-time extensibility point, available to any package that uses it. So the sandboxed `dotnet build` (against a trivial scratch source file, wrapped in `strace`) traces this real, broader surface. The NuGet sandbox runs in a small `mcr.microsoft.com/dotnet/sdk:8.0` + `strace` image built and cached locally the first time it's needed -- no plugin pre-warming needed, unlike Maven's `compile` goal. Like Cargo/Go/Maven, Trivy scans a host-side `packages.lock.json` built before the container runs (via a real, networked `dotnet restore` against the resolved set) -- Trivy's NuGet support needs a real lock file, detecting nothing from a bare `.csproj`.

## Install vs Scan

`install` and `scan` use the same fast/deep validation logic.

The only difference is:

- `install` installs on the host after the checks pass
- `scan` stops after the checks and does not install anything

This same behavior applies to:

- direct package names
- multiple package names in one command
- `requirements.txt`
- `uv.lock`
- `pyproject.toml`

## npm / yarn / pnpm Support

`depshieldx` can resolve, check, and install npm packages too, with full fast and deep mode support.

Two ways to point it at npm:

**A lockfile in the current directory** -- auto-detected by filename, no flag needed:

```bash
depshieldx scan --lockfile package-lock.json
depshieldx scan --lockfile yarn.lock
depshieldx scan --lockfile pnpm-lock.yaml
depshieldx install --lockfile package-lock.json
```

**One or more bare package names** -- pass `--ecosystem npm` so `depshieldx` knows they aren't PyPI names:

```bash
depshieldx scan left-pad --ecosystem npm
depshieldx install left-pad --ecosystem npm
depshieldx install left-pad is-odd --ecosystem npm
```

Bare package-name resolution shells out to the real `npm` CLI in an isolated temp directory to compute the full, accurate transitive dependency tree, then checks that whole resolved set before installing. Installing pins each requested package to the exact version that was just checked (`npm install left-pad@1.3.0`), not a floating range, so nothing can drift to a different release between the scan and the install.

If you have the [routing shim](#routing) enabled, `npm install <package>` is also intercepted automatically and routed through `depshieldx install <package> --ecosystem npm` -- you don't need to change your muscle memory.

npm/yarn/pnpm now has full functional parity with PyPI: `--deep` (Docker + Trivy + real behavioral tracing via strace), `depshieldx uninstall`, and cryptographic provenance verification (real Sigstore bundle verification of npm's SLSA provenance attestations, not just presence checks -- see [Provenance And Attestations](#provenance-and-attestations)) are all supported.

What's still explicitly **not** supported for npm/yarn/pnpm:

- `requirements.txt`/`pyproject.toml`-style inputs -- those formats are inherently PyPI-specific; use a lockfile or `--ecosystem npm` instead

## Cargo / crates.io Support

`depshieldx` can resolve, check, and install Cargo crates too, with full fast and deep mode support.

Two ways to point it at Cargo:

**A `Cargo.lock` file in the current directory** -- auto-detected by filename, no flag needed:

```bash
depshieldx scan --lockfile Cargo.lock
depshieldx install --lockfile Cargo.lock
```

**One or more bare crate names** -- pass `--ecosystem cargo` so `depshieldx` knows they aren't PyPI names:

```bash
depshieldx scan serde --ecosystem cargo
depshieldx install serde --ecosystem cargo
depshieldx install serde tokio --ecosystem cargo
```

Bare crate-name resolution shells out to the real `cargo add` CLI against a scratch package in an isolated temp directory to compute the full, accurate resolved dependency set, then checks that whole resolved set before installing.

If you have the [routing shim](#routing) enabled, `cargo add <crate>` is also intercepted automatically and routed through `depshieldx install <crate> --ecosystem cargo` -- you don't need to change your muscle memory.

"Install" here means `cargo add` -- adding the crate(s) to your project's `Cargo.toml`/`Cargo.lock` -- not `cargo install` (installing a binary crate). `depshieldx` does not currently support installing binary crates.

`--deep` is supported for Cargo the same way it is for PyPI and npm: the resolved crate set is fetched into a sandboxed container (`rust:1-slim` + `strace`) and scanned with Trivy, and the sandboxed `cargo build --offline` is traced with `strace` for filesystem, process, and network activity -- see [Modes](#modes) for details. `depshieldx uninstall` is also supported, via `cargo remove`.

Provenance checks for Cargo are structural only, not cryptographic: crates.io has no Sigstore/SLSA attestation infrastructure to verify against, unlike PyPI and npm. Checks are limited to things like yanked-release status and registry metadata -- see [Provenance And Attestations](#provenance-and-attestations).

What's still explicitly **not** supported for Cargo:

- installing binary crates (`cargo install`) -- `depshieldx`'s Cargo support only covers dependency crates added via `cargo add`
- `Cargo.toml`-as-input -- only `Cargo.lock` or bare crate names via `--ecosystem cargo` are accepted
- cryptographic provenance verification -- crates.io has nothing to verify against

## Go Modules Support

`depshieldx` can resolve, check, and install Go modules too, with full fast and deep mode support.

Two ways to point it at Go:

**A `go.sum` file in the current directory** -- auto-detected by filename, no flag needed:

```bash
depshieldx scan --lockfile go.sum
depshieldx install --lockfile go.sum
```

**One or more bare module paths** -- pass `--ecosystem go` so `depshieldx` knows they aren't PyPI names:

```bash
depshieldx scan github.com/pkg/errors --ecosystem go
depshieldx install github.com/pkg/errors --ecosystem go
depshieldx install github.com/pkg/errors golang.org/x/text --ecosystem go
```

Bare module-path resolution shells out to the real `go get` CLI against a scratch module in an isolated temp directory to compute the full, accurate resolved module graph -- `go.sum` alone can't reconstruct it, since it's a checksum allowlist (it can list more versions of a module than actually ship, every version Minimal Version Selection considered, not just the winner), not the resolved graph itself. `--lockfile go.sum` resolution reads the sibling `go.mod`'s directory the same way, via `go list -m all`.

If you have the [routing shim](#routing) enabled, `go get <module>` is also intercepted automatically and routed through `depshieldx install <module> --ecosystem go` -- you don't need to change your muscle memory.

"Install" here means `go get` -- adding the module(s) to your project's `go.mod`/`go.sum` -- not `go install` (installing a binary program; since Go 1.18, `go get` itself never builds or installs anything). `depshieldx` does not currently support installing binary programs.

`--deep` is supported for Go the same way it is for PyPI, npm, and Cargo: the resolved module set is fetched into a sandboxed container (`golang:1-bookworm` + `strace`) via a local file-based Go module proxy built on the host, and scanned with Trivy -- Trivy reads `go.mod`/`go.sum` natively, needing no extracted source tree the way Cargo's vendor directory does. The sandboxed `go build` is traced with `strace` for filesystem, process, and network activity -- see [Modes](#modes) for details. Not every resolved module has an importable root package (some are subpackage-only, like `golang.org/x/crypto`); those are gracefully skipped from behavioral tracing rather than failing the whole build, and recorded as skipped in the full JSON report. `depshieldx uninstall` is also supported, via `go get <module>@none`.

Provenance checks for Go are structural only, not cryptographic: crates.io-style attestation infrastructure doesn't exist for Go modules either. Checksum verification against Go's real checksum-transparency log (sum.golang.org) already happens transparently inside the `go` toolchain itself during resolution -- what `depshieldx` checks independently is the `retract` directive (a module author retracting a previously published version), the closest Go equivalent to PyPI's/Cargo's yanked-release signal -- see [Provenance And Attestations](#provenance-and-attestations).

What's still explicitly **not** supported for Go:

- installing binary programs (`go install`) -- `depshieldx`'s Go support only covers dependency modules added via `go get`
- `go.mod`-as-input -- only `go.sum` or bare module paths via `--ecosystem go` are accepted
- cryptographic provenance verification of the kind PyPI/npm have (per-package Sigstore signing) -- Go's real checksum-transparency verification already happens inside the `go` toolchain itself, not as a separate `depshieldx`-driven step

## Maven / Maven Central Support

`depshieldx` can resolve, check, and install Maven coordinates too, with full fast and deep mode support.

Maven has no canonical lockfile to auto-detect the way `Cargo.lock`/`go.sum`/`package-lock.json` do, so coordinates are always passed explicitly with `--ecosystem maven`:

```bash
depshieldx scan org.apache.commons:commons-lang3:3.18.0 --ecosystem maven
depshieldx install com.google.code.gson:gson:2.11.0 --ecosystem maven
depshieldx install org.apache.commons:commons-lang3 --ecosystem maven
```

A bare `groupId:artifactId` (no version) resolves to that coordinate's latest release via Maven Central's search API. Resolution shells out to the real `mvn` CLI against a scratch `pom.xml` in an isolated temp directory (`dependency:list`) to compute the full, accurate transitive dependency graph, the same reasoning as Cargo's/Go's scratch-project resolve.

"Install" here means fetching every resolved coordinate -- transitive dependencies included, not just the ones you named -- into your local repository (`~/.m2`), pinned exactly so nothing can drift between scan and install. There is no `depshieldx uninstall` support for Maven: `mvn dependency:get`/`dependency:resolve` only ever download into the local repository, they never edit a `pom.xml` the way `cargo remove`/`go get @none` edit their manifests, so there's nothing well-defined to reverse. There is also no [routing shim](#routing) for Maven -- unlike `pip install`/`npm install`/`cargo add`/`go get`, Maven has no native CLI verb for "add a dependency" to intercept; dependencies are added by editing `pom.xml` directly.

`--deep` is supported for Maven the same way it is for PyPI, npm, Cargo, and Go: the resolved coordinate set (every real `.jar` and `.pom`, plus every `<parent>` POM and `<dependencyManagement>` BOM import needed to resolve them, walked recursively) is fetched into a sandboxed container (`maven:3-eclipse-temurin-21` + `strace`, with Maven's own default-lifecycle plugin set pre-warmed into the image at build time) and scanned with Trivy -- Trivy reads the scratch `pom.xml` natively. The sandboxed `mvn compile` is traced with `strace` for filesystem, process, and network activity -- see [Modes](#modes) for details. Unlike Cargo's `build.rs` or Go's `init()`, a jar consumed as a plain Maven dependency runs no code automatically; the one real exception is an annotation processor registered via `META-INF/services`, which gets discovered and invoked by `javac` during any compile it's present for -- ordinary libraries that register no processor correctly trace zero build-time activity.

Provenance checks for Maven combine checksum verification (SHA-256 where published, falling back to SHA-1 for older releases -- MD5 is never trusted), structural PGP-signature presence (Maven Central has required PGP signatures since the 2010s, but with no central root of trust `depshieldx` can verify against), and real cryptographic Sigstore verification where a publisher has opted in (supported by Maven Central's Publisher Portal since January 2025) -- see [Provenance And Attestations](#provenance-and-attestations).

What's still explicitly **not** supported for Maven:

- `depshieldx uninstall` -- see above, there's no well-defined manifest edit to reverse
- the [routing shim](#routing) -- Maven has no native "add a dependency" CLI command to intercept
- `pom.xml`-as-input -- only explicit `groupId:artifactId[:version]` coordinates via `--ecosystem maven` are accepted, no lockfile or manifest auto-detection

## NuGet Support

`depshieldx` can resolve, check, and install NuGet packages too, with full fast and deep mode support.

Two ways to point it at NuGet:

**A `packages.lock.json` file in the current directory** -- auto-detected by filename, no flag needed:

```bash
depshieldx scan --lockfile packages.lock.json
depshieldx install --lockfile packages.lock.json
```

**One or more bare package names** -- pass `--ecosystem nuget` so `depshieldx` knows they aren't PyPI names:

```bash
depshieldx scan Newtonsoft.Json --ecosystem nuget
depshieldx install Newtonsoft.Json --ecosystem nuget
depshieldx install Newtonsoft.Json@13.0.3 --ecosystem nuget
```

A bare package name (no version) resolves to that package's latest version via NuGet.org's search API. Resolution shells out to the real `dotnet restore` CLI against a scratch `.csproj` in an isolated temp directory to compute the full, accurate transitive dependency graph, the same reasoning as Cargo's/Go's/Maven's scratch-project resolve.

If you have the [routing shim](#routing) enabled, `dotnet add package <name>` is also intercepted automatically and routed through `depshieldx install <name> --ecosystem nuget` -- you don't need to change your muscle memory.

"Install" here means `dotnet add package` -- adding the package to your project's `.csproj`/`packages.lock.json`. Unlike Maven, `depshieldx uninstall` is supported for NuGet, via `dotnet remove package`. Both directions are scoped to exactly one package per invocation -- `dotnet add package`/`dotnet remove package` themselves only ever accept a single package name.

`--deep` is supported for NuGet the same way it is for PyPI, npm, Cargo, Go, and Maven: the resolved package set (every real `.nupkg`) is fetched into a sandboxed container (`mcr.microsoft.com/dotnet/sdk:8.0` + `strace`) and scanned with Trivy against a real, host-generated `packages.lock.json` -- Trivy's NuGet support needs a real lock file, it detects nothing from a bare `.csproj`. The sandboxed `dotnet build` is traced with `strace` for filesystem, process, and network activity -- see [Modes](#modes) for details. Unlike Maven's narrow annotation-processor exception, any package shipping a `build/*.targets` or `build/*.props` file gets it imported and evaluated during `dotnet build`, MSBuild's own general build-time extensibility point.

Provenance checks for NuGet combine a real cryptographic checksum check (SHA-512, verified against the exact hash NuGet.org's registration API publishes for that release) with structural repository-signature presence -- NuGet.org has no Sigstore/SLSA equivalent, but unlike Maven's opt-in PGP/Sigstore signing, it does unconditionally repository-sign every package it hosts with an X.509/Authenticode signature -- see [Provenance And Attestations](#provenance-and-attestations).

What's still explicitly **not** supported for NuGet:

- `.csproj`-as-input -- only `packages.lock.json` or bare package names via `--ecosystem nuget` are accepted
- cryptographic chain verification of the repository signature -- `depshieldx` has no trust-root/certificate-chain-validation story for X.509 elsewhere, so presence is recorded structurally, the same way Maven's PGP-signature presence is

## Commands

Main commands:

- `depshieldx install`
- `depshieldx scan`
- `depshieldx uninstall`
- `depshieldx ui`
- `depshieldx routing status`
- `depshieldx routing enable`
- `depshieldx routing disable`
- `depshieldx receipts list`
- `depshieldx receipts verify <path>`
- `depshieldx receipts delete`

Get help at any level:

```bash
depshieldx --help
depshieldx install --help
depshieldx scan --help
depshieldx uninstall --help
depshieldx ui --help
depshieldx receipts --help
```

## Local UI

`depshieldx ui` opens a local, read-only browser view over cached receipts and related cache entries.

- binds to `127.0.0.1` only
- uses port `0` by default so the OS can choose a free port
- opens the browser automatically unless you pass `--no-open`

Examples:

```bash
depshieldx ui
depshieldx ui --port 8765
depshieldx ui --no-open
```

## Release Notes

For a release build:

- confirm the included Apache 2.0 license still matches how you want to distribute the project
- build and verify distributions in a Python `3.11.4+` environment
- run `python -m build`
- run `python -m twine check dist/*`
- for TestPyPI, run the `Release Checks` workflow manually
- for PyPI, push a version tag such as `v0.1.0` -- this also triggers the `Release Binaries` workflow, which builds and attaches the standalone per-platform binaries to the matching GitHub Release

## Common Examples

Install one package:

```bash
depshieldx install fastapi
```

Install multiple packages:

```bash
depshieldx install langchain requests --deep
```

Scan only:

```bash
depshieldx scan fastapi --fast
depshieldx scan fastapi --deep
```

Use a requirements file:

```bash
depshieldx install -r requirements.txt
depshieldx scan -r requirements.txt --deep
```

Use a lockfile:

```bash
depshieldx install --lockfile uv.lock
depshieldx scan --lockfile uv.lock
```

Use a `pyproject.toml` file:

```bash
depshieldx install --pyproject pyproject.toml
depshieldx scan --pyproject pyproject.toml --deep
```

Open the local cache UI:

```bash
depshieldx ui
depshieldx ui --port 8765
depshieldx ui --no-open
```

Uninstall packages:

```bash
depshieldx uninstall requests
depshieldx uninstall -r requirements.txt
depshieldx uninstall --pyproject pyproject.toml
```

npm packages and lockfiles:

```bash
depshieldx scan left-pad --ecosystem npm
depshieldx install left-pad --ecosystem npm
depshieldx install left-pad is-odd --ecosystem npm
depshieldx scan --lockfile package-lock.json
depshieldx install --lockfile yarn.lock
depshieldx scan --lockfile pnpm-lock.yaml
```

Cargo crates and lockfiles:

```bash
depshieldx scan serde --ecosystem cargo
depshieldx install serde --ecosystem cargo
depshieldx install serde tokio --ecosystem cargo
depshieldx scan --lockfile Cargo.lock
depshieldx install --lockfile Cargo.lock
```

Go modules and lockfiles:

```bash
depshieldx scan github.com/pkg/errors --ecosystem go
depshieldx install github.com/pkg/errors --ecosystem go
depshieldx install github.com/pkg/errors golang.org/x/text --ecosystem go
depshieldx scan --lockfile go.sum
depshieldx install --lockfile go.sum
```

Maven coordinates:

```bash
depshieldx scan org.apache.commons:commons-lang3:3.18.0 --ecosystem maven
depshieldx install com.google.code.gson:gson:2.11.0 --ecosystem maven
depshieldx install org.apache.commons:commons-lang3 --ecosystem maven
```

NuGet packages and lockfiles:

```bash
depshieldx scan Newtonsoft.Json --ecosystem nuget
depshieldx install Newtonsoft.Json@13.0.3 --ecosystem nuget
depshieldx scan --lockfile packages.lock.json
depshieldx install --lockfile packages.lock.json
```

## Supported Inputs

`depshieldx` accepts:

- one package name (PyPI by default, npm with `--ecosystem npm`, Cargo/crates.io with `--ecosystem cargo`, Go with `--ecosystem go`, Maven coordinates with `--ecosystem maven`, or NuGet with `--ecosystem nuget`)
- multiple package names (same ecosystem rule as above)
- `-r requirements.txt` (PyPI only)
- `--lockfile uv.lock` (PyPI)
- `--lockfile package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` (npm, auto-detected by filename)
- `--lockfile Cargo.lock` (Cargo, auto-detected by filename)
- `--lockfile go.sum` (Go, auto-detected by filename)
- `--lockfile packages.lock.json` (NuGet, auto-detected by filename)
- `--pyproject pyproject.toml` (PyPI only)

Maven has no canonical lockfile, so it has no `--lockfile` equivalent -- coordinates are always passed explicitly via `--ecosystem maven`.

Current lockfile behavior:

- `uv.lock` is parsed directly
- `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` are parsed directly
- `Cargo.lock` is parsed directly; if the same crate is pinned at two different major versions, only the newest resolved version is kept and the older entry is silently dropped
- `go.sum` resolution reads the sibling `go.mod`'s full resolved module graph (via `go list -m all`) rather than parsing `go.sum` itself, since `go.sum` is a checksum allowlist, not the resolved graph -- it can list more module versions than actually ship
- `packages.lock.json` is parsed directly; if a package appears across multiple target frameworks with disagreeing versions, only the newest resolved version is kept, the same "keep the newest" rule as `Cargo.lock`
- other PyPI lockfile-style inputs are treated like requirement-style pinned targets

## Output Modes

Human-readable summary:

```bash
depshieldx install requests --output summary
```

JSON only:

```bash
depshieldx install requests --output json
```

Summary plus JSON:

```bash
depshieldx install requests --output both
depshieldx install requests --full-report
```

## What The Summary Means

Key summary lines:

- `Scan verdict`
- `CVE sources across all resolved packages`
- `Provenance verdict`
- `Attestation verification`
- `Sandbox verdict`
- `Trivy verdict`
- `Host install`
- `Receipts`

`Scan verdict` reflects the resolved package set, including dependencies.

`Provenance verdict` means the provenance checks did or did not block. A package can still pass provenance and show informational items such as:

- missing author or maintainer email
- missing PyPI attestations

That is expected. `passed` means "not blocked", not "perfect metadata".

`Attestation verification` describes how many attested selected files verified successfully. It does not mean every package had attestations.

`historical/fixed` CVEs mean the source knows about past vulnerabilities in the package history, but not in the exact versions currently selected for install.

Example summary:

```text
Summary
Package: fastapi
Mode: fast
Install target: fastapi==0.135.2
Resolved packages: 10
Scan verdict: passed with 0 warning(s), 0 info item(s)
CVE sources across all resolved packages:
  • cisa-kev: no vulnerabilities
  • deps-dev: 0 advisories, 10 package record(s) checked
  • github-advisories: no vulnerabilities
  • osv: 0 affecting resolved version(s), 15 historical/fixed entries in resolved dependency history
Provenance verdict: passed with 0 warning(s), 0 info item(s)
Attestation verification: 7/7 attested file(s) verified, available
Host install: succeeded (fastapi==0.135.2, https://pypi.org/project/fastapi/0.135.2/)
Receipts: allowed (1 package receipt)
Receipt ID: abc123def4567890
Receipt path:
  - /Users/you/.depshieldx-cache/receipts/20260331T000000Z-fastapi-0.135.2-abc123def4567890.json
```

For multi-package installs, the summary also includes:

- a requested-package source breakdown
- one receipt path per requested package
- one project link (PyPI, npm, crates.io, pkg.go.dev, or nuget.org) per requested package when relevant

## Provenance And Attestations

The provenance stage checks the exact artifacts selected for your environment, not every file on the release page.

For PyPI, it looks at things like:

- whether the release exists on PyPI
- whether the release is source-only
- whether the release is a pre-release
- whether homepage/project URLs exist
- whether author or maintainer email metadata exists
- whether the selected files have PyPI attestations
- whether those attestations verify successfully (a real Sigstore bundle check, not just presence)

For npm/yarn/pnpm, it looks at:

- whether the release is deprecated
- whether homepage/repository and author/maintainer metadata exist
- whether the resolved release has an integrity digest
- whether the release has npm provenance attestations, and whether its SLSA provenance attestation (the one signed via GitHub Actions OIDC through a real Fulcio certificate) verifies successfully -- npm's separate "publish" attestation, signed with npm registry's own key rather than a Fulcio certificate, is recorded but not cryptographically verified here, since that's a different trust model

For Cargo/crates.io, there is no cryptographic attestation infrastructure to check against -- crates.io does not support Sigstore/SLSA provenance the way PyPI and npm do. Instead, `depshieldx` checks:

- whether the resolved version has been yanked
- whether homepage/repository metadata exists
- crates.io's self-reported Trusted Publishing metadata (provider, repository, run ID), where present -- recorded for reference only, since crates.io does not sign or publish a verifiable attestation for it

For Go modules, checksum verification against the real checksum-transparency log (sum.golang.org, a cryptographically-signed Merkle tree) already happens transparently inside the `go` toolchain itself during resolution -- there's no separate per-package attestation to verify the way PyPI/npm have. Instead, `depshieldx` checks:

- whether the resolved version has been retracted (a module author publishing a later version that lists a prior one as retracted -- Go's closest equivalent to a yanked release)
- basic module metadata

For Maven/Maven Central, provenance combines a checksum with structural and (where available) real cryptographic signals:

- checksum verification (SHA-256 where Central publishes one, falling back to SHA-1 for older releases -- MD5 is never trusted, it's cryptographically broken)
- whether the resolved artifact has a PGP signature (Central has required these since the 2010s) -- presence is recorded structurally only, since there's no central root of trust binding an arbitrary PGP key to a real-world identity the way Sigstore's Fulcio certificates are
- whether the resolved artifact has a Sigstore bundle and, if so, whether it verifies successfully (a real cryptographic check, not just presence) -- supported by Maven Central's Publisher Portal since January 2025, but still new and opt-in; most published artifacts don't have one yet

For NuGet/NuGet.org, provenance combines a real cryptographic checksum check with structural signature-presence:

- checksum verification (SHA-512, verified against the exact hash NuGet.org's own registration API publishes for that release -- a real cryptographic hash comparison, not a structural check)
- whether the resolved package has a repository signature -- NuGet.org unconditionally repository-signs every package it hosts with an X.509/Authenticode signature, so presence is checked directly against the `.nupkg`'s own signature entry, but the certificate chain itself is not cryptographically validated, the same "presence, not chain verification" limitation as Maven's PGP-signature check
- whether the resolved version is unlisted (NuGet's structural yank-equivalent) or marked deprecated

Either way, a block only happens when verification was actually attempted and failed -- not attestations being absent at all, since most packages on PyPI and npm don't publish them, Cargo/Go have no per-package attestations to check in the first place, and most Maven artifacts published today are PGP-only, not yet Sigstore-signed.

## Vulnerability Sources

Fast and deep mode both query these four sources concurrently:

- OSV
- GitHub Advisories
- CISA KEV
- deps.dev

`deps.dev` output is shown as:

```text
deps-dev: 0 advisories, 43 package record(s) checked
```

That means:

- how many advisory references deps.dev reported
- how many resolved package-version records were successfully checked

## Receipts

Every completed install or scan attempts to write signed local receipt JSON files.

Important receipt behavior:

- single-package runs produce one receipt
- multi-package runs produce one receipt per requested package
- requirements, lockfile, and `pyproject.toml` runs also write per-requested-package receipts when possible

Receipt commands:

```bash
depshieldx receipts list
depshieldx receipts verify ~/.depshieldx-cache/receipts/<receipt>.json
depshieldx receipts delete
```

Receipts include package-level details such as:

- package and resolved version
- project link
- provenance summary
- scan summary
- historical/fixed CVE entries for that package

## Routing

`depshieldx` can optionally install small shims so simple `pip install <package>`, `npm install [package]`, `yarn install`, `pnpm install`, `cargo add <crate>`, `go get <module>`, and `dotnet add package <name>` commands go through `depshieldx`.

```bash
depshieldx routing status
depshieldx routing enable
depshieldx routing disable
```

Routing is platform-aware:

- on macOS and Linux it creates shell shims (`pip`, `npm`, `yarn`, `pnpm`, `cargo`, `go`, `dotnet`)
- on Windows it creates batch shims (`pip.bat`, `npm.bat`, `yarn.bat`, `pnpm.bat`, `cargo.bat`, `go.bat`, `dotnet.bat`)

What each shim intercepts:

- `pip install <package>` -- a single package name, routed through `depshieldx install <package>`
- `npm install` / `npm i` / `npm ci` / `yarn install` / `pnpm install` with no package named -- routed through `depshieldx install --lockfile <lockfile-in-cwd>`, only when that lockfile is present
- `npm install <package...>` / `npm i <package...>` -- one or more package names with no other flags, routed through `depshieldx install <package...> --ecosystem npm`
- `yarn add <package>` / `pnpm add <package>` are **not** intercepted yet -- ad-hoc resolution in this phase only covers `npm install <package>`, so yarn/pnpm named installs pass straight through to the real tool
- `cargo add <crate...>` -- one or more crate names with no other flags, routed through `depshieldx install <crate...> --ecosystem cargo`. `cargo install` (binary crates) is not intercepted -- depshieldx's cargo support only covers `cargo add`
- `go get <module...>` -- one or more module paths with no other flags, routed through `depshieldx install <module...> --ecosystem go`. `go install` (binary programs) is not intercepted -- depshieldx's Go support only covers `go get`
- `dotnet add package <name>` / `dotnet add package <name> --version <version>` -- exactly one package, no other flags, routed through `depshieldx install <name>[@version] --ecosystem nuget`. No project positional and no other `dotnet add package` flags (`--framework`, `--prerelease`, ...) are intercepted -- anything beyond this exact shape passes straight through to the real `dotnet`

There is no Maven shim, and none is planned -- unlike `pip install`/`npm install`/`cargo add`/`go get`/`dotnet add package`, `mvn` has no native CLI verb for "add a dependency" to intercept in the first place; Maven dependencies are added by editing `pom.xml` directly. See [Maven / Maven Central Support](#maven--maven-central-support).

Anything else (flags mixed in with a package name, other subcommands like `run`, global installs) passes straight through to the real tool untouched.

Useful environment variables:

- `DEPSHIELDX_CACHE_DIR`
- `DEPSHIELDX_RECEIPTS_DIR`
- `DEPSHIELDX_NO_ROUTING_PROMPT=1`
- `DEPSHIELDX_ROUTE_DEEP=1`

## Cache Location

By default, local state lives under:

```text
~/.depshieldx-cache
```

That directory can contain:

- provenance cache entries
- deep-scan cache entries
- receipts
- routing state

You can inspect those cached results in the local browser UI with:

```bash
depshieldx ui
```

## Exit Codes

- `0`: success
- `10`: blocked by resolution, provenance, vulnerability checks, or Trivy
- `11`: deep mode could not use Docker and the install or scan was skipped for that reason
- `12`: host install was attempted but failed

## Limitations

- deep mode depends on Docker being available (for npm, a small local `node:20` + `strace` image is built on first use; for Cargo, a small local `rust:1-slim` + `strace` image is built on first use; for Go, a small local `golang:1-bookworm` + `strace` image is built on first use; for Maven, a small local `maven:3-eclipse-temurin-21` + `strace` image, with Maven's own default-lifecycle plugin set pre-warmed in, is built on first use; for NuGet, a small local `mcr.microsoft.com/dotnet/sdk:8.0` + `strace` image is built on first use -- see [npm / yarn / pnpm Support](#npm--yarn--pnpm-support), [Cargo / crates.io Support](#cargo--cratesio-support), [Go Modules Support](#go-modules-support), [Maven / Maven Central Support](#maven--maven-central-support), and [NuGet Support](#nuget-support))
- deep mode also depends on Trivy being installed
- deep mode is slower than fast mode
- npm's, Cargo's, Go's, Maven's, and NuGet's behavioral tracing (Docker deep mode) all observe syscalls via `strace` rather than actively blocking them in real time the way PyPI's in-process guards do; filesystem/network isolation is still enforced by the container itself either way
- the safety guarantees depend in part on the local Python and `pip` versions
- Cargo resolution, install, and deep mode all shell out to a local `cargo` on `PATH`; there is no preflight check for this, so a missing Rust toolchain only surfaces later, as a resolution failure
- Go resolution, install, and deep mode all shell out to a local `go` on `PATH` the same way; there is no preflight check for this either, so a missing Go toolchain only surfaces later, as a resolution failure
- Maven resolution, install, and deep mode all shell out to a local `mvn` on `PATH` the same way; there is no preflight check for this either, so a missing Java/Maven toolchain only surfaces later, as a resolution failure
- NuGet resolution, install, and deep mode all shell out to a local `dotnet` on `PATH` the same way; there is no preflight check for this either, so a missing .NET SDK only surfaces later, as a resolution failure
- `Cargo.lock` parsing keeps only the newest resolved version when the same crate appears pinned at two different major versions; the older entry is silently dropped -- `packages.lock.json` parsing follows the same "keep the newest" rule when a package disagrees across target frameworks
- not every Go module resolved for deep mode has an importable root package (some are subpackage-only, e.g. `golang.org/x/crypto`); those are skipped from behavioral tracing rather than failing the whole sandboxed build, and listed in the full JSON report's `skipped_modules`
- some packages publish no PyPI or npm attestations at all; that is usually informational, not a red flag -- Cargo/crates.io and Go modules have no per-package attestation infrastructure at all, so this is categorically true for every crate/module, not just some; Maven has real Sigstore support but it's still new and opt-in, so most Maven artifacts today are in the same boat; NuGet has no Sigstore equivalent at all
- attestation verification can depend on upstream trust metadata availability
- npm's own "publish" attestation (signed with npm registry's own key, not a Fulcio certificate) is recorded structurally but not cryptographically verified -- only npm's SLSA provenance attestation is, since that's the one signed via GitHub Actions OIDC the same way PyPI's Trusted Publishing attestations are
- Cargo has no cryptographic provenance verification at all -- crates.io currently has nothing equivalent to verify against
- Go modules have no separate per-package cryptographic provenance step either -- checksum verification against the real checksum-transparency log already happens transparently inside the `go` toolchain itself during resolution
- Maven's Sigstore verification only recognizes one confirmed-real OIDC issuer (GitHub Actions) for now -- a real signature from a different, equally-legitimate issuer is recorded as "signed via Sigstore, but by an unrecognized issuer" (informational), not verified as trusted
- a BOM import's version that's a `${property}` placeholder is resolved for Maven deep mode only against that same POM's own `<properties>` block, not Maven's fuller cross-file property inheritance -- an unresolvable entry is skipped rather than guessed at, and surfaces as a clear Maven error from the sandboxed build if it turns out to matter
- there is no Maven routing shim -- see [Routing](#routing)
- NuGet's repository-signature check is presence-only, not a real certificate-chain validation -- `depshieldx` has no trust-root story for X.509 elsewhere, so a forged or expired certificate chain would still record as "signed"
- both `dotnet add package` and `dotnet remove package` (and so `depshieldx`'s own NuGet install/uninstall/routing) are scoped to exactly one package per invocation -- the real `dotnet` CLI itself doesn't accept more than one package name at a time
- vulnerability-source coverage depends on the upstream services

## FAQ

### Does it scan dependencies too?

Yes. The resolved dependency set is scanned, not just the top-level package you typed.

### Will `install --deep` and `scan --deep` behave the same way?

Yes, except `install` performs the final host install and `scan` does not.

### What should I use most of the time?

Use:

```bash
depshieldx install <package>
```

Use `--deep` when you want the extra Docker + Trivy validation step.
