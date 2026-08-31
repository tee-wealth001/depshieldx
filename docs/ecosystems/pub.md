# Pub Support

`depshieldx` can resolve, check, and install Pub (Dart/Flutter) packages too, with
full fast and deep mode support.

Two ways to point it at Pub:

**A `pubspec.lock` file in the current directory** -- auto-detected by filename,
no flag needed:

```bash
depshieldx scan --lockfile pubspec.lock
depshieldx install --lockfile pubspec.lock
```

**One or more bare package names** -- pass `--ecosystem pub` so `depshieldx`
knows they aren't PyPI names:

```bash
depshieldx scan http --ecosystem pub
depshieldx install http --ecosystem pub
depshieldx install http@1.6.0 --ecosystem pub
```

A bare package name (no version) resolves to that package's latest version via
pub.dev's own package API. Resolution shells out to the real `dart pub get` CLI
against a scratch `pubspec.yaml` in an isolated temp directory to compute the full,
accurate transitive dependency graph, the same reasoning as Cargo's/Go's/Maven's/
NuGet's scratch-project resolve.

If you have the [routing shim](../cli/routing.md) enabled,
`dart pub add <package...>` is also intercepted automatically and routed through
`depshieldx install <package...> --ecosystem pub` -- you don't need to change
your muscle memory.

"Install" here means `dart pub add` -- adding the package(s) to your project's
`pubspec.yaml`/`pubspec.lock`. Unlike NuGet's `dotnet add package` (limited to one
package per invocation), `dart pub add foo bar` accepts any number of packages in one
call, so `depshieldx` pins every resolved package -- transitive included --
as a direct dependency in one call, the same stronger scan-to-install drift guarantee
Cargo/Go already have. `depshieldx uninstall` is also supported, via
`dart pub remove` (also multi-package).

`--deep` is supported the same way it is for PyPI, npm, Cargo, Go, Maven, and NuGet:
the resolved package set (every real `.tar.gz` archive) is fetched into a sandboxed
container (`dart:3` + `strace`) and scanned with Trivy against a real, host-generated
`pubspec.lock` -- Trivy's Pub support needs a real lock file, the same
requirement NuGet's own support has. The sandboxed `dart run` (against a trivial
scratch entry-point file) is traced with `strace` for filesystem, process, and
network activity -- see [Modes](../concepts/modes.md) for details. Pub's real
code-execution surface is Dart's Native Assets "hooks" feature (`hook/build.dart`)
-- a package shipping one gets it invoked during `dart run`/`dart test`, the
same "presence in the dependency graph is enough" pattern NuGet's `build/*.targets`
has, not something `dart pub get` alone ever triggers.

Provenance checks for Pub combine a real cryptographic checksum check (SHA-256,
verified against the exact hash pub.dev's own package API publishes for that
release) with structural signals -- pub.dev has no signing scheme of its own at
all (no Sigstore, no PGP, no X.509), so integrity rests entirely on this checksum
-- see [Provenance & Attestations](../concepts/provenance.md).

!!! note
    deps.dev does not support Pub as an ecosystem at all -- `depshieldx` skips it
    explicitly for Pub scans rather than silently querying the wrong system, so
    `deps-dev: no vulnerabilities` for a Pub scan means "not checked", not "checked
    and clean".

## Not supported

- `pubspec.yaml`-as-input -- only `pubspec.lock` or bare package names via
  `--ecosystem pub` are accepted
- cryptographic signature verification of any kind -- pub.dev has no signing
  infrastructure to verify against, unlike Maven/NuGet
- Flutter-specific tooling (native platform plugin builds, `flutter pub`,
  `flutter build`) -- `depshieldx`'s Pub support is scoped to the standalone
  Dart SDK and hosted (pub.dev) dependencies only
