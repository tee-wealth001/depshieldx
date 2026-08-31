# Limitations

- deep mode depends on Docker being available (for npm, a small local `node:20` +
  `strace` image is built on first use; for Cargo, a small local `rust:1-slim` +
  `strace` image is built on first use; for Go, a small local `golang:1-bookworm` +
  `strace` image is built on first use; for Maven, a small local
  `maven:3-eclipse-temurin-21` + `strace` image, with Maven's own default-lifecycle
  plugin set pre-warmed in, is built on first use; for NuGet, a small local
  `mcr.microsoft.com/dotnet/sdk:8.0` + `strace` image is built on first use; for
  Pub, a small local `dart:3` + `strace` image is built on first use; for RubyGems,
  a small local `ruby:3` + `strace` image is built on first use; for Composer, a
  small local `php:8.4-cli` + `strace` image, plus the `zip` PHP extension and
  `unzip`, and Composer itself copied from the official `composer:2` image, is
  built on first use) -- see the [ecosystems overview](ecosystems/index.md)
- deep mode also depends on Trivy being installed
- deep mode is slower than fast mode
- npm's, Cargo's, Go's, Maven's, NuGet's, Pub's, RubyGems', and Composer's
  behavioral tracing (Docker deep mode) all observe syscalls via `strace` rather
  than actively blocking them in real time the way PyPI's in-process guards do;
  filesystem/network isolation is still enforced by the container itself either way
- the safety guarantees depend in part on the local Python and `pip` versions
- Cargo, Go, Maven, NuGet, Pub, RubyGems, and Composer resolution/install/deep mode
  all shell out to a local toolchain binary on `PATH` (`cargo`, `go`, `mvn`,
  `dotnet`, `dart`, `bundle`, `composer` respectively); `install`/`scan` themselves
  still don't preflight-check any of these before attempting resolution, so a
  missing toolchain surfaces as a resolution failure mid-run. Run
  `depshieldx doctor` first to check every ecosystem's toolchain (plus
  Docker/Trivy and the Python/pip prerequisite every operation needs) up front
  instead
- `Cargo.lock` parsing keeps only the newest resolved version when the same crate
  appears pinned at two different major versions; the older entry is silently
  dropped -- `packages.lock.json` parsing follows the same "keep the newest"
  rule when a package disagrees across target frameworks
- not every Go module resolved for deep mode has an importable root package (some
  are subpackage-only, e.g. `golang.org/x/crypto`); those are skipped from
  behavioral tracing rather than failing the whole sandboxed build, and listed in
  the full JSON report's `skipped_modules`
- some packages publish no PyPI or npm attestations at all; that is usually
  informational, not a red flag -- Cargo/crates.io and Go modules have no
  per-package attestation infrastructure at all, so this is categorically true for
  every crate/module, not just some; Maven has real Sigstore support but it's
  still new and opt-in, so most Maven artifacts today are in the same boat;
  NuGet, Pub, RubyGems, and Composer have no default Sigstore equivalent at all
- attestation verification can depend on upstream trust metadata availability
- npm's own "publish" attestation (signed with npm registry's own key, not a
  Fulcio certificate) is recorded structurally but not cryptographically verified
  -- only npm's SLSA provenance attestation is, since that's the one signed
  via GitHub Actions OIDC the same way PyPI's Trusted Publishing attestations are
- Cargo has no cryptographic provenance verification at all -- crates.io
  currently has nothing equivalent to verify against
- Go modules have no separate per-package cryptographic provenance step either
  -- checksum verification against the real checksum-transparency log
  already happens transparently inside the `go` toolchain itself during
  resolution
- Maven's Sigstore verification only recognizes one confirmed-real OIDC issuer
  (GitHub Actions) for now -- a real signature from a different, equally
  legitimate issuer is recorded as "signed via Sigstore, but by an unrecognized
  issuer" (informational), not verified as trusted
- a BOM import's version that's a `${property}` placeholder is resolved for Maven
  deep mode only against that same POM's own `<properties>` block, not Maven's
  fuller cross-file property inheritance -- an unresolvable entry is skipped
  rather than guessed at, and surfaces as a clear Maven error from the sandboxed
  build if it turns out to matter
- there is no Maven routing shim -- see [Routing](cli/routing.md)
- NuGet's repository-signature check is presence-only, not a real
  certificate-chain validation -- `depshieldx` has no trust-root story for
  X.509 elsewhere, so a forged or expired certificate chain would still record as
  "signed"
- both `dotnet add package` and `dotnet remove package` (and so `depshieldx`'s
  own NuGet install/uninstall/routing) are scoped to exactly one package per
  invocation -- the real `dotnet` CLI itself doesn't accept more than one
  package name at a time
- Pub has no cryptographic signature verification at all -- pub.dev has no
  Sigstore/PGP/X.509 signing scheme to verify against, unlike Maven/NuGet;
  integrity rests entirely on the SHA-256 checksum check
- deps.dev does not support Pub as an ecosystem at all -- `depshieldx` skips
  it explicitly rather than silently querying the wrong system, so a Pub scan's
  `deps-dev: no vulnerabilities` means "not checked", not "checked and clean"
- Pub's behavioral tracing only covers Dart's Native Assets "hooks" mechanism
  (`hook/build.dart`) -- Flutter-specific native platform plugin code
  (compiled during an actual `flutter build`, not anything `dart run`/
  `dart pub get` trigger) is out of scope, since `depshieldx`'s Pub support
  targets the standalone Dart SDK, not Flutter
- RubyGems has no cryptographic signature verification at all -- Sigstore
  support for rubygems.org is still opt-in/in-progress and the older X.509
  `gem cert` scheme is rarely used in practice, so integrity rests entirely on
  the SHA-256 checksum check, the same as Pub
- a RubyGems version yanked long enough ago is removed outright from the
  registry rather than staying queryable with a `yanked: true` flag (confirmed
  against the real 2019 `rest-client` hijack incident) -- since a 404 there
  is ambiguous between "never existed" and "yanked and purged", `depshieldx`
  reports it as an honest, non-blocking warning rather than asserting a confirmed
  yank
- `depshieldx` never runs `bundle install`/`bundle lock --local` on the host for
  RubyGems deep mode -- `bundle install` triggers real native-extension
  compilation, unlike every other ecosystem's own host-side restore/fetch step;
  the Trivy-facing `Gemfile.lock` is written directly from the already-known
  resolution instead, and only the fully-isolated sandbox container actually
  runs `bundle install`
- platform-specific RubyGems variants (a gem publishing separate prebuilt
  binaries per OS/CPU) are out of scope -- `depshieldx` always resolves and
  verifies against the platform-agnostic "ruby" build, matching what a real
  `bundle lock` and rubygems.org's own per-version API both default to
- Composer has no cryptographic signature verification of any kind --
  Packagist has no Sigstore/PGP/X.509 signing scheme to verify against at all,
  unlike Maven/NuGet, and most packages don't even publish a checksum to fall
  back on; integrity for those packages rests entirely on the git commit
  `reference` Packagist records for the resolved dist archive
- deps.dev does not support Composer/PHP as an ecosystem at all, the same gap it
  has for Pub -- `depshieldx` skips it explicitly rather than silently
  querying the wrong system, so a Composer scan's `deps-dev: no vulnerabilities`
  means "not checked", not "checked and clean"
- Composer's behavioral tracing only covers packages using the "files" autoload
  mechanism -- Composer plugins (blocked by default as of 2.2+ unless the
  project explicitly allow-lists one, which `depshieldx` never does) and
  project-level script hooks (root-project-only by design, never triggered by a
  dependency's own `composer.json`) are both out of scope, since neither is a
  real risk in `depshieldx`'s own default, unmodified install flow
- `depshieldx` never runs `composer install`/`composer update` on the host to
  build the Trivy-facing `composer.lock` for Composer deep mode -- a
  minimal, hand-written lockfile (just each package's name and version) is
  already sufficient for Trivy's own vulnerability detection, so `depshieldx`
  writes it directly from the resolution it already has instead
- vulnerability-source coverage depends on the upstream services
