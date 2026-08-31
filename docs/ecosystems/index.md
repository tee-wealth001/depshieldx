# Ecosystems Overview

`depshieldx` supports nine package ecosystems, each with fast-mode provenance +
vulnerability checks and full deep-mode Docker + Trivy behavioral tracing.

| Ecosystem | Lockfile auto-detect | Ecosystem flag | Routing shim | Uninstall | Cryptographic provenance |
|---|---|---|---|---|---|
| PyPI | `uv.lock`, `requirements.txt`, `pyproject.toml` | *(default)* | `pip` | Yes | Yes (Sigstore) |
| [npm / yarn / pnpm](npm.md) | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `--ecosystem npm` | `npm` | Yes | Yes (Sigstore SLSA) |
| [Cargo / crates.io](cargo.md) | `Cargo.lock` | `--ecosystem cargo` | `cargo` | Yes | No (structural only) |
| [Go Modules](go.md) | `go.sum` | `--ecosystem go` | `go` | Yes | No (checksums verified by `go` itself) |
| [Maven / Maven Central](maven.md) | *(none)* | `--ecosystem maven` | *(none)* | No | Partial (opt-in Sigstore since Jan 2025) |
| [NuGet](nuget.md) | `packages.lock.json` | `--ecosystem nuget` | `dotnet` | Yes | Checksum + X.509 presence |
| [Pub](pub.md) | `pubspec.lock` | `--ecosystem pub` | `dart` | Yes | Checksum only |
| [RubyGems](rubygems.md) | `Gemfile.lock` | `--ecosystem rubygems` | `bundle` | Yes | Checksum only |
| [Composer](composer.md) | `composer.lock` | `--ecosystem composer` | `composer` | Yes | Weakest &mdash; git ref pin, rarely a checksum |

Each ecosystem page covers:

- how to point `depshieldx` at it (lockfile vs. bare package name)
- what "install" and "uninstall" map to for that ecosystem's real CLI
- deep-mode sandbox image and what behavioral tracing observes
- provenance model
- what's explicitly **not** supported

See [Modes](../concepts/modes.md) for the shared fast/deep mechanics, and
[Provenance & Attestations](../concepts/provenance.md) for the full per-ecosystem
provenance breakdown.
