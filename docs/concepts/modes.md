# Modes (Fast vs Deep)

`depshieldx` has two modes:

- `fast`
- `deep`

Plain `install` and plain `scan` default to `fast`.

`deep` is supported for PyPI, npm/yarn/pnpm, Cargo/crates.io, Go modules,
Maven/Maven Central, NuGet/NuGet.org, Pub/pub.dev, RubyGems/rubygems.org, and
Composer/Packagist input.

## Fast mode

Fast mode:

- resolves the exact package versions that would be installed
- checks provenance for the resolved package set
- queries OSV, GitHub Advisories, CISA KEV, and deps.dev
- blocks if any resolved package or dependency is reported as vulnerable by the
  blocking sources

Fast mode does not use Docker or Trivy.

## Deep mode

Deep mode does everything in fast mode first, then:

- installs the resolved package set in Docker
- runs Trivy on the sandboxed install result
- blocks if the Docker environment is unavailable or Trivy returns blocking findings

For `install --deep`, the host install only happens after the fast checks and the
Docker + Trivy stage both pass.

`depshieldx` shells out to the local `pip` (or, for npm, the local `npm`; for Cargo,
the local `cargo`; for Go, the local `go`; for Maven, the local `mvn`; for NuGet, the
local `dotnet`; for Pub, the local `dart`; for RubyGems, the local `bundle`; for
Composer, the local `composer`) for resolution, download, and host install steps, so
keeping those tools up to date is part of the security model.

### Behavioral tracing, per ecosystem

!!! info "How each ecosystem is traced"

    === "PyPI"

        Deep mode traces filesystem writes, subprocess launches, and network access
        in-process during the sandboxed install (via `sys.addaudithook`) and actively
        blocks disallowed ones in real time.

    === "npm / yarn / pnpm"

        npm has no equivalent in-process hook, so behavioral tracing instead wraps the
        sandboxed `npm install` in `strace`, observing the same categories of activity
        across the whole install (including lifecycle scripts) rather than blocking
        individual syscalls live &mdash; filesystem/network isolation is still enforced
        by the container itself either way. The npm sandbox runs in a small `node:20` +
        `strace` image `depshieldx` builds and caches locally the first time it's
        needed.

    === "Cargo"

        Cargo/crates.io behavioral tracing works the same way as npm's: the sandboxed
        `cargo build --offline` runs wrapped in `strace`, observing filesystem,
        process, and network activity (including `build.rs` scripts and proc-macros)
        rather than blocking individual syscalls live. The Cargo sandbox runs in a
        small `rust:1-slim` + `strace` image built and cached locally the first time
        it's needed. One mechanical difference from npm/PyPI: since there's no new
        installed output that needs to survive the sandbox, Trivy scans a host-side
        vendor directory of the resolved `.crate` files (checksum-verified against
        crates.io) built before the container runs, rather than a bind-mounted install
        destination.

    === "Go"

        Go modules behavioral tracing works the same way: the sandboxed `go build`
        runs wrapped in `strace`, observing filesystem, process, and network activity
        (`init()` functions and `//go:generate`-produced code are Go's equivalent of
        Cargo's `build.rs`/proc-macros) rather than blocking individual syscalls live.
        The Go sandbox runs in a small `golang:1-bookworm` + `strace` image built and
        cached locally the first time it's needed. Like Cargo, Trivy scans a host-side
        `go.mod`/`go.sum` pair built before the container runs &mdash; Trivy reads Go's
        manifest files natively, needing no extracted source tree the way Cargo's
        vendor directory does. One Go-specific wrinkle: unlike Cargo (which compiles
        every declared dependency regardless of use), Go only compiles what's actually
        imported, so a scratch program blank-imports every resolved module to force
        real compilation &mdash; and not every module has an importable root package
        (some are subpackage-only, e.g. `golang.org/x/crypto`). Those are skipped from
        tracing rather than failing the whole build, and listed in the full JSON
        report's `skipped_modules`.

    === "Maven"

        Maven behavioral tracing is different in one fundamental way: unlike Cargo's
        `build.rs` or Go's `init()`, a jar consumed as a plain Maven dependency has no
        code that runs automatically just by being resolved, or even sitting on the
        compile classpath. The one real exception is an annotation processor
        registered via `META-INF/services` (Lombok, MapStruct, Dagger, and similar)
        &mdash; `javac` auto-discovers and invokes it during any compile it's present
        for, regardless of whether the compiled source actually uses its target
        annotations. So the sandboxed `mvn compile` (against a trivial scratch source
        file, wrapped in `strace`) traces real activity for that class of dependency,
        and genuinely zero extra activity for the (large majority) of ordinary
        libraries that register no processor &mdash; an accurate verdict, not a
        coverage gap. The Maven sandbox runs in a small
        `maven:3-eclipse-temurin-21` + `strace` image built and cached locally the
        first time it's needed, with Maven's own default-lifecycle plugin set
        pre-warmed into the image at build time. Like Cargo/Go, Trivy scans a
        host-side scratch `pom.xml` built before the container runs, listing every
        resolved coordinate as a pinned direct dependency.

    === "NuGet"

        NuGet behavioral tracing has the broadest code-execution surface of the four
        compiled ecosystems: a `.nupkg` consumed as a plain `PackageReference` has no
        code that runs automatically during `dotnet restore` alone, but any package
        shipping a `build/*.targets` or `build/*.props` file gets it imported and
        evaluated during `dotnet build` &mdash; not a narrow processor-registration
        mechanism like Maven's, but MSBuild's own general build-time extensibility
        point, available to any package that uses it. So the sandboxed `dotnet build`
        (against a trivial scratch source file, wrapped in `strace`) traces this real,
        broader surface. The NuGet sandbox runs in a small
        `mcr.microsoft.com/dotnet/sdk:8.0` + `strace` image built and cached locally
        the first time it's needed &mdash; no plugin pre-warming needed, unlike
        Maven's `compile` goal. Like Cargo/Go/Maven, Trivy scans a host-side
        `packages.lock.json` built before the container runs (via a real, networked
        `dotnet restore` against the resolved set) &mdash; Trivy's NuGet support needs
        a real lock file, detecting nothing from a bare `.csproj`.

    === "Pub"

        Pub's own real code-execution surface is Dart's official Native Assets
        "hooks" feature: a package can ship a `hook/build.dart` file (a real Dart
        entry point, typically used to compile a native C/Rust library) that the
        toolchain invokes for the root package and every transitive dependency during
        `dart run`/`dart test` &mdash; confirmed this fires even when nothing actually
        imports the package, the same "presence in the dependency graph is enough"
        pattern Maven's/NuGet's own surfaces have. `dart pub get` alone never triggers
        hooks &mdash; so the sandboxed `dart run` (against a trivial scratch
        entry-point file, wrapped in `strace`) is what actually traces this surface;
        `dart compile exe` was deliberately not used instead, since it refuses to run
        hooks at all. The Pub sandbox runs in a small `dart:3` + `strace` image built
        and cached locally the first time it's needed. Like the other ecosystems,
        Trivy scans a host-side `pubspec.lock` built before the container runs (via a
        real, offline `dart pub get` against the resolved set's own freshly-built
        local package cache).

    === "RubyGems"

        RubyGems behavioral tracing looks different from every other ecosystem here
        in one fundamental way: a native-extension gem's own `extconf.rb` build
        script runs as an unavoidable, inherent part of *installing* the gem itself,
        not a separate later run/build step &mdash; so there's no clean split between
        "resolve/restore, unstraced" and "run/build, straced". `bundle install` is
        never safe to run on the host at all &mdash; unlike
        `cargo fetch --locked`/`go mod download`/`dotnet restore`/`dart pub get`, none
        of which invoke a compiler, `bundle install` genuinely compiles native code
        for any gem that ships one. So `depshieldx` never shells out to
        `bundle install`/`bundle lock` on the host to build the Trivy-facing
        lockfile; it writes `Gemfile.lock` directly from the resolution it already has
        (itself produced by a real, safe `bundle lock` scratch resolve). The sandboxed
        `bundle install --local` &mdash; the same command Docker deep mode's offline
        install step already runs &mdash; is what gets wrapped in `strace` instead.
        The RubyGems sandbox runs in a small `ruby:3` + `strace` image built and
        cached locally the first time it's needed &mdash; deliberately not `-slim`,
        since it needs to ship a real C toolchain (gcc/make) for native-extension
        compilation to succeed (nokogiri, sqlite3, pg, bcrypt, ...).

    === "Composer"

        Composer behavioral tracing targets a narrower, but real and non-opt-in,
        surface: a plain `composer install --no-plugins --no-scripts` never executes a
        dependency's own code at all &mdash; Composer 2.2+ blocks any package
        containing a Composer plugin by default unless the project explicitly
        allow-lists it (`depshieldx` never does), and Composer's script hooks are
        root-project-only by design. The real surface is PHP's own "files" autoload
        mechanism: a package can declare
        `"autoload": {"files": ["bootstrap.php"]}`, and that file executes
        unconditionally the moment anything actually loads the generated
        `vendor/autoload.php` &mdash; even with zero explicit reference to the
        package's own classes &mdash; unlike ordinary PSR-4 class autoloading, which
        is lazy. So the sandboxed install runs `composer install` unstraced first
        (already proven safe), then straces a trivial scratch probe script that does
        nothing but load the autoloader. The Composer sandbox runs in a small
        `php:8.4-cli` + `strace` image built and cached locally the first time it's
        needed, with the `zip` PHP extension and `unzip` added, and Composer itself
        copied from the official `composer:2` image.

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
