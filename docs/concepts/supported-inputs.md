# Supported Inputs

`depshieldx` accepts:

- one package name (PyPI by default, npm with `--ecosystem npm`, Cargo/crates.io with
  `--ecosystem cargo`, Go with `--ecosystem go`, Maven coordinates with
  `--ecosystem maven`, NuGet with `--ecosystem nuget`, Pub with `--ecosystem pub`,
  RubyGems with `--ecosystem rubygems`, or Composer with `--ecosystem composer`)
- multiple package names (same ecosystem rule as above)
- `-r requirements.txt` (PyPI only)
- `--lockfile uv.lock` (PyPI)
- `--lockfile package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` (npm, auto-detected
  by filename)
- `--lockfile Cargo.lock` (Cargo, auto-detected by filename)
- `--lockfile go.sum` (Go, auto-detected by filename)
- `--lockfile packages.lock.json` (NuGet, auto-detected by filename)
- `--lockfile pubspec.lock` (Pub, auto-detected by filename)
- `--lockfile Gemfile.lock` (RubyGems, auto-detected by filename)
- `--lockfile composer.lock` (Composer, auto-detected by filename)
- `--pyproject pyproject.toml` (PyPI only)

Maven has no canonical lockfile, so it has no `--lockfile` equivalent &mdash;
coordinates are always passed explicitly via `--ecosystem maven`.

## Lockfile parsing behavior

- `uv.lock` is parsed directly
- `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` are parsed directly
- `Cargo.lock` is parsed directly; if the same crate is pinned at two different major
  versions, only the newest resolved version is kept and the older entry is silently
  dropped
- `go.sum` resolution reads the sibling `go.mod`'s full resolved module graph (via
  `go list -m all`) rather than parsing `go.sum` itself, since `go.sum` is a checksum
  allowlist, not the resolved graph &mdash; it can list more module versions than
  actually ship
- `packages.lock.json` is parsed directly; if a package appears across multiple target
  frameworks with disagreeing versions, only the newest resolved version is kept, the
  same "keep the newest" rule as `Cargo.lock`
- `pubspec.lock` is parsed directly (it's real YAML); only `source: hosted` entries
  are resolved against the registry &mdash; `source: git`/`source: path`/`source: sdk`
  entries have no registry checksum to verify against and are skipped
- `Gemfile.lock` is parsed directly (Bundler's own custom text format, not
  YAML/JSON); only the `GEM` section's resolved specs are read &mdash; `GIT`/`PATH`
  sections have no registry checksum to verify against and are skipped
- `composer.lock` is parsed directly (it's real JSON); direct-vs-transitive
  dependency status is read from the sibling `composer.json`'s own
  `require`/`require-dev` tables, since neither of `composer.lock`'s own
  `packages`/`packages-dev` arrays marks its entries either way
- other PyPI lockfile-style inputs are treated like requirement-style pinned targets
