# Composer Support

`depshieldx` can resolve, check, and install Composer (PHP/Packagist) packages too,
with full fast and deep mode support.

Two ways to point it at Composer:

**A `composer.lock` file in the current directory** -- auto-detected by
filename, no flag needed:

```bash
depshieldx scan --lockfile composer.lock
depshieldx install --lockfile composer.lock
```

**One or more bare package names** -- pass `--ecosystem composer` so
`depshieldx` knows they aren't PyPI names:

```bash
depshieldx scan monolog/monolog --ecosystem composer
depshieldx install monolog/monolog --ecosystem composer
depshieldx install monolog/monolog@3.10.0 --ecosystem composer
```

Unlike Pub/RubyGems/NuGet, a bare package name (no version) needs no separate
registry lookup -- `composer require vendor/package` (with no version at all)
already resolves and pins the latest stable release by itself. Resolution shells out
to the real `composer require --no-install` CLI against a scratch `composer.json` in
an isolated temp directory to compute the full, accurate transitive dependency
graph, the same reasoning as Cargo's/Go's/Maven's/NuGet's/Pub's/RubyGems' own
scratch-project resolve -- `--no-install` skips straight past Composer's own
extract/activate step, so a scratch resolve never has anything to gain from (or risk
on) it succeeding.

If you have the [routing shim](../cli/routing.md) enabled,
`composer require <package...>` is also intercepted automatically and routed
through `depshieldx install <package...> --ecosystem composer` -- you don't
need to change your muscle memory.

"Install" here means `composer require` -- adding the package(s) to your
project's `composer.json`/`composer.lock`. Unlike RubyGems' `bundle add` (one
shared `--version` across every named gem in a call), a real
`composer require pkg1:v1 pkg2:v2 ...` accepts any number of independently-versioned
packages in one call -- so `depshieldx` pins every resolved package,
transitive included, as a direct dependency in one call, the same stronger
scan-to-install drift guarantee Cargo/Go/Pub already have. `depshieldx uninstall`
is also supported, via `composer remove` (also multi-package).

`--deep` is supported the same way it is for PyPI, npm, Cargo, Go, Maven, NuGet,
Pub, and RubyGems: the resolved package set (every real dist `.zip`,
checksum-verified when the registry actually publishes one) is fetched into a
sandboxed container (`php:8.4-cli` + `strace`) and installed fully offline through
Composer's own real "artifact" repository mechanism, then scanned with Trivy
against a real, host-written `composer.lock`. Unlike NuGet/Pub, that lockfile is
never produced by running `composer` on the host at all -- a minimal,
hand-written `composer.lock` (just each package's name and version) is already
sufficient for Trivy's own vulnerability detection, so `depshieldx` writes it
directly from the resolution it already has, the same "don't shell out again for no
reason" choice RubyGems makes (for an entirely different underlying reason --
Composer has no comparable installation-time code-execution risk to isolate). See
[Modes](../concepts/modes.md) for how the sandboxed install itself is traced.

Provenance checks for Composer are the weakest of any ecosystem here, and honestly
so: Packagist's own `dist.shasum` is empty for essentially every real package, so
there is usually no checksum to verify at all. When a checksum genuinely is
published, it's still verified as a real SHA-1 hash; when it isn't, `depshieldx`
says so plainly ("no checksum published -- pinned by git reference only")
rather than refusing or pretending it verified something it didn't. The git commit
`reference` Packagist records for the resolved dist archive is the one real,
always-present content pin. Structurally, `depshieldx` also surfaces Packagist's
`abandoned` flag, which can be a plain boolean or a string naming a suggested
replacement package -- see
[Provenance & Attestations](../concepts/provenance.md).

!!! note
    Like Pub, deps.dev does **not** support Composer/PHP as an ecosystem at all
    -- `depshieldx` skips it explicitly for Composer scans rather than
    silently querying the wrong system, so `deps-dev: no vulnerabilities` for a
    Composer scan means "not checked", not "checked and clean".

## Not supported

- `composer.json`-as-input -- only `composer.lock` or bare package names via
  `--ecosystem composer` are accepted
- cryptographic signature verification of any kind -- Packagist has no
  Sigstore/PGP/X.509 signing scheme to verify against, unlike Maven/NuGet, and most
  packages don't even publish a checksum to fall back on
- Composer plugins -- as of Composer 2.2+, installing any package containing
  one is blocked by default unless explicitly allow-listed in the project's own
  `config.allow-plugins`; `depshieldx` relies on this default rather than working
  around it, and never allow-lists anything itself
