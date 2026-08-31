# RubyGems Support

`depshieldx` can resolve, check, and install RubyGems packages too, with full fast and
deep mode support.

Two ways to point it at RubyGems:

**A `Gemfile.lock` file in the current directory** -- auto-detected by filename,
no flag needed:

```bash
depshieldx scan --lockfile Gemfile.lock
depshieldx install --lockfile Gemfile.lock
```

**One or more bare gem names** -- pass `--ecosystem rubygems` so `depshieldx`
knows they aren't PyPI names:

```bash
depshieldx scan rack --ecosystem rubygems
depshieldx install rack --ecosystem rubygems
depshieldx install rack@3.2.7 --ecosystem rubygems
```

A bare gem name (no version) resolves to that gem's latest version via
rubygems.org's own gem API. Resolution shells out to the real `bundle lock` CLI
against a scratch `Gemfile` in an isolated temp directory to compute the full,
accurate transitive dependency graph, the same reasoning as Cargo's/Go's/Maven's/
NuGet's/Pub's scratch-project resolve. Only the `GEM` section of a `Gemfile.lock`
(rubygems.org-hosted gems) is resolved against the registry -- `GIT`/`PATH`
sections have no registry checksum to verify against and are skipped.

If you have the [routing shim](../cli/routing.md) enabled, `bundle add <gem...>` is
also intercepted automatically and routed through
`depshieldx install <gem...> --ecosystem rubygems` -- you don't need to change
your muscle memory.

"Install" here means `bundle add` -- adding the gem(s) to your project's
`Gemfile`/`Gemfile.lock`. Unlike Cargo's/Go's/Pub's own "name@version" per-target
syntax, `bundle add gem1 gem2 --version X` applies ONE shared version constraint to
every named gem in the call -- there's no way to pin more than one
independently-resolved exact version in a single invocation. So `depshieldx` loops
one real `bundle add <gem> --version <v>` call per resolved gem instead, still
ending up with every resolved gem -- transitive included -- pinned as a
direct dependency, the same drift-prevention guarantee Cargo/Go/Pub already have.
`depshieldx uninstall` is also supported, via `bundle remove` (multi-gem in one
call).

`--deep` is supported the same way it is for PyPI, npm, Cargo, Go, Maven, NuGet, and
Pub: the resolved gem set (every real `.gem` archive) is fetched into a sandboxed
container (`ruby:3` + `strace`) and scanned with Trivy against a real
`Gemfile.lock` -- Trivy's Bundler support needs a real lock file, the same
requirement NuGet's/Pub's own support has. Unlike every other ecosystem here, that
`Gemfile.lock` is never produced by actually running `bundle` on the host:
`bundle install`/`bundle lock --local` either triggers real native-extension
compilation or can't reliably resolve purely from a local cache, so `depshieldx`
writes it directly from the resolution it already has instead. The sandboxed
`bundle install --local` (the same command Docker deep mode's install step already
runs) is what's traced with `strace` for filesystem, process, and network activity
-- see [Modes](../concepts/modes.md) for details. RubyGems' real
code-execution surface is a native-extension gem's own `extconf.rb`, run as an
unavoidable part of installing it -- not a separate later step the way Pub's
hooks/NuGet's `build/*.targets` are.

Provenance checks for RubyGems combine a real cryptographic checksum check
(SHA-256, verified against the exact hash rubygems.org's own API publishes for that
release) with a structural yank signal -- see
[Provenance & Attestations](../concepts/provenance.md). Unlike NuGet's "unlisted"
(still resolvable/queryable when pinned exactly) or Pub's "retracted" (stays in the
registry's own version list forever, just flagged), a RubyGems version yanked long
enough ago is removed outright -- confirmed against the real 2019
`rest-client` hijack incident (1.6.10-1.6.13): both the full versions list and the
per-version registry endpoint have no record of it at all, a plain 404 rather than a
`yanked: true` payload. Since that 404 is genuinely ambiguous between "never
existed" and "yanked and purged", `depshieldx` surfaces it as an honest,
non-blocking "could not verify this version" warning rather than asserting a
specific cause it can't actually confirm.

Unlike Pub, deps.dev does support RubyGems as an ecosystem -- no explicit skip
needed here.

## Not supported

- `.gemspec`-as-input -- only `Gemfile.lock` or bare gem names via
  `--ecosystem rubygems` are accepted
- cryptographic signature verification of any kind -- rubygems.org's Sigstore
  support is still opt-in/in-progress, and the older X.509 `gem cert` scheme is
  opt-in and rarely used in practice, so integrity rests entirely on the SHA-256
  checksum check, the same as Pub
- platform-specific gem variants (a gem publishing separate prebuilt binaries per
  OS/CPU) -- `depshieldx` always resolves and verifies against the
  platform-agnostic "ruby" build, matching what a real `bundle lock` and
  rubygems.org's own per-version API both default to when no platform is specified
