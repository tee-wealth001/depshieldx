# depshieldx

[![PyPI version](https://img.shields.io/pypi/v/depshieldx.svg)](https://pypi.org/project/depshieldx/)
[![Docs](https://img.shields.io/badge/docs-github%20pages-10b981)](https://tee-wealth001.github.io/depshieldx/)

`depshieldx` is a safer wrapper around package install and scan workflows, for both PyPI (Python) and npm/yarn/pnpm (JavaScript) -- see [npm / yarn / pnpm Support](#npm--yarn--pnpm-support) for the npm-specific details.

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
- **Deep mode**, for either ecosystem, additionally requires Docker.

Project links:

- PyPI: https://pypi.org/project/depshieldx/
- Docs: https://tee-wealth001.github.io/depshieldx/
- Source: https://github.com/tee-wealth001/depshieldx

## What It Does

- resolves the full dependency set before installation, for PyPI or npm/yarn/pnpm
- checks provenance for the selected release artifacts (PyPI attestations, or npm's SLSA provenance attestations -- both verified cryptographically via real Sigstore bundle verification, not just presence checks)
- queries 4 vulnerability sources for the resolved package versions:
  - OSV
  - GitHub Advisories
  - CISA KEV
  - deps.dev
- supports a deeper Docker + Trivy scan mode, plus real syscall-level behavioral tracing during sandboxed installs, for both PyPI and npm/yarn/pnpm
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

`deep` is supported for both PyPI and npm/yarn/pnpm input.

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

`depshieldx` shells out to the local `pip` (or, for npm, the local `npm`) for resolution, download, and host install steps, so keeping those tools up to date is part of the security model.

For PyPI, deep mode also traces filesystem writes, subprocess launches, and network access in-process during the sandboxed install (via `sys.addaudithook`) and actively blocks disallowed ones in real time. For npm, which has no equivalent in-process hook, behavioral tracing instead wraps the sandboxed `npm install` in `strace`, observing the same categories of activity across the whole install (including lifecycle scripts) rather than blocking individual syscalls live -- filesystem/network isolation is still enforced by the container itself either way. The npm sandbox runs in a small `node:20` + `strace` image `depshieldx` builds and caches locally the first time it's needed.

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

## Supported Inputs

`depshieldx` accepts:

- one package name (PyPI by default, or npm with `--ecosystem npm`)
- multiple package names (same ecosystem rule as above)
- `-r requirements.txt` (PyPI only)
- `--lockfile uv.lock` (PyPI)
- `--lockfile package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` (npm, auto-detected by filename)
- `--pyproject pyproject.toml` (PyPI only)

Current lockfile behavior:

- `uv.lock` is parsed directly
- `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` are parsed directly
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
- one PyPI project link per requested package when relevant

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

Either way, a block only happens when verification was actually attempted and failed -- not attestations being absent at all, since most packages on both registries don't publish them.

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

`depshieldx` can optionally install small shims so simple `pip install <package>`, `npm install [package]`, `yarn install`, and `pnpm install` commands go through `depshieldx`.

```bash
depshieldx routing status
depshieldx routing enable
depshieldx routing disable
```

Routing is platform-aware:

- on macOS and Linux it creates shell shims (`pip`, `npm`, `yarn`, `pnpm`)
- on Windows it creates batch shims (`pip.bat`, `npm.bat`, `yarn.bat`, `pnpm.bat`)

What each shim intercepts:

- `pip install <package>` -- a single package name, routed through `depshieldx install <package>`
- `npm install` / `npm i` / `npm ci` / `yarn install` / `pnpm install` with no package named -- routed through `depshieldx install --lockfile <lockfile-in-cwd>`, only when that lockfile is present
- `npm install <package...>` / `npm i <package...>` -- one or more package names with no other flags, routed through `depshieldx install <package...> --ecosystem npm`
- `yarn add <package>` / `pnpm add <package>` are **not** intercepted yet -- ad-hoc resolution in this phase only covers `npm install <package>`, so yarn/pnpm named installs pass straight through to the real tool

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

- deep mode depends on Docker being available (for npm, a small local `node:20` + `strace` image is built on first use -- see [npm / yarn / pnpm Support](#npm--yarn--pnpm-support))
- deep mode also depends on Trivy being installed
- deep mode is slower than fast mode
- npm's behavioral tracing (Docker deep mode) observes syscalls via `strace` rather than actively blocking them in real time the way PyPI's in-process guards do; filesystem/network isolation is still enforced by the container itself either way
- the safety guarantees depend in part on the local Python and `pip` versions
- some packages publish no PyPI or npm attestations at all; that is usually informational, not a red flag
- attestation verification can depend on upstream trust metadata availability
- npm's own "publish" attestation (signed with npm registry's own key, not a Fulcio certificate) is recorded structurally but not cryptographically verified -- only npm's SLSA provenance attestation is, since that's the one signed via GitHub Actions OIDC the same way PyPI's Trusted Publishing attestations are
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
