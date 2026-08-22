"""Parses `Gemfile.lock` -- Bundler's own custom text format, not YAML/JSON/
TOML the way most other ecosystems' lockfiles here are, confirmed directly
against a real `bundle lock` run, shaped like:

```
GEM
  remote: https://rubygems.org/
  specs:
    activesupport (7.1.0)
      base64
      bigdecimal
      concurrent-ruby (~> 1.0, >= 1.0.2)
    concurrent-ruby (1.3.8)
    rack (3.2.7)
    rack-test (2.1.0)
      rack (>= 1.3)

PLATFORMS
  x64-mingw-ucrt

DEPENDENCIES
  activesupport (= 7.1.0)
  rack-test (= 2.1.0)

CHECKSUMS
  activesupport (7.1.0) sha256=01a20b75b86ffb3b3bf014c6611fecf12a27cb9f0bbdc1c794f5d5c3e1e9fcf6
  rack (3.2.7) sha256=93e13e1c24f93556671d85d2d79fa228c3485815c50d7e2f265b5330c6528fb7

BUNDLED WITH
  4.0.16
```

Confirmed directly (real `bundle lock` output): top-level sections start at
column 0 ("GEM", "GIT", "PATH", "PLATFORMS", "DEPENDENCIES", "CHECKSUMS",
"BUNDLED WITH", ...); a resolved gem's own spec line is indented exactly 4
spaces under a "GEM" section's "  specs:" line, `<name> (<version>)`; a
6-space-or-deeper indented line directly below it is that gem's own
dependency *requirement* annotation (e.g. "      rack (>= 1.3)"), not a
separately resolved package -- confirmed directly these can even be bare
names with no version/requirement at all ("      base64"). Only the exact
4-space-indented lines are read here; everything else under a spec is
skipped, the same "don't misparse a nested annotation as a top-level
resolved entry" concern Maven's own tokenizer docstring raises for a
different format.

Only "GEM" sections (rubygems.org-hosted, or another real Gem source, but
never git-/path-sourced) are read -- "GIT"/"PATH" sections use the exact
same nested "specs:" shape (confirmed directly against a real git-sourced
Gemfile.lock) but have no registry checksum to verify against, mirroring
how pubspec.lock's `source: hosted`-only filtering already treats
non-registry-sourced dependencies as out of scope here.

Platform-specific spec entries ("name (version-platform)", e.g. a gem
that ships prebuilt per-platform binaries) are a real, documented
Gemfile.lock shape, but were not reproduced by a real `bundle lock` on
this system even after deliberately forcing multiple non-local platforms
(confirmed directly: nokogiri 1.16.0 still resolved to the plain,
platform-agnostic "ruby" build both with and without extra `--add-
platform` flags) -- matching registry.py's own confirmed-directly finding
that the per-version API endpoint defaults to that same "ruby" platform
variant. Given that, and that a hyphen in a *version* (not a platform
suffix) is itself unusual for a real published gem (RubyGems' own
Gem::Version normalizes a hyphenated prerelease like "2.0.0-rc1" to
".pre." internally, and the convention is discouraged), a hyphen inside a
spec line's parenthesized content is treated here as a platform
separator: everything before the first "-" is kept as the version,
anything after is a platform tag and is dropped. Platform selection
itself stays out of scope for this module, consistent with registry.py.

`DEPENDENCIES` entries are Bundler's real equivalent of NuGet's
packages.lock.json "type": "Direct" field / pubspec.lock's "dependency":
"direct ..." field -- confirmed directly these are exactly (and only) the
gems declared in the project's own Gemfile, used the same way by
direct_dependency_names(). A non-default-source dependency (git/path/
otherwise added) gets a trailing "!" marker with no parenthesized
requirement at all (confirmed directly: "  rack!") -- stripped here along
with any "(requirement)" suffix to recover the bare gem name either way.
"""

import re

_SPEC_LINE = re.compile(r"^    ([A-Za-z0-9_.-]+) \(([^)]+)\)\s*$")
_DEPENDENCY_LINE = re.compile(r"^  ([A-Za-z0-9_.-]+?)!?(?: \([^)]*\))?\s*$")


def _split_spec_version_platform(raw: str) -> str:
    version, _, _platform = raw.partition("-")
    return version


def parse_gemfile_lock(lockfile_path: str) -> dict[str, str]:
    resolved_versions: dict[str, str] = {}
    current_section = None
    in_specs = False

    with open(lockfile_path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue
            if not line.startswith(" "):
                current_section = line.strip()
                in_specs = False
                continue
            if current_section != "GEM":
                continue
            if line == "  specs:":
                in_specs = True
                continue
            if not in_specs:
                continue

            match = _SPEC_LINE.match(line)
            if not match:
                continue
            name, raw_version = match.group(1), match.group(2)
            resolved_versions[name] = _split_spec_version_platform(raw_version)

    return resolved_versions


def direct_dependency_names(lockfile_path: str) -> list[str]:
    """Names a user would expect `depshieldx uninstall --lockfile
    Gemfile.lock ...` to remove: gems declared directly in the project's
    Gemfile (the DEPENDENCIES section), not every transitively-resolved
    gem the lockfile also lists -- mirrors PubEcosystem's/NuGetEcosystem's
    own direct_dependency_names_for_lockfile exactly, using Bundler's own
    analogous section."""
    names = []
    current_section = None

    with open(lockfile_path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue
            if not line.startswith(" "):
                current_section = line.strip()
                continue
            if current_section != "DEPENDENCIES":
                continue

            match = _DEPENDENCY_LINE.match(line)
            if match:
                names.append(match.group(1))

    return names


def write_gemfile_lock(resolved_versions: dict[str, str]) -> str:
    """Serializes an already-known, already-real resolution (produced by
    a genuine `bundle lock` run or by parsing a real Gemfile.lock -- see
    ecosystem.py's resolve()) back into Bundler's own lockfile text
    format, for the one case that needs to reproduce a Gemfile.lock
    without re-invoking bundle: runner.py's prepare_rubygems_download_bundle,
    which deliberately never runs `bundle install`/`bundle lock` on the
    host at all (confirmed directly this triggers real native-extension
    compilation -- see rubygems_sandbox.Dockerfile's module docstring).

    Every resolved package (transitive included) is written as both a
    GEM spec entry and a DEPENDENCIES entry, exactly pinned -- confirmed
    directly this round-trips cleanly through a real `bundle install
    --local` (used only inside the fully-isolated sandbox container,
    never on the host) with "Found no changes, using resolution from the
    lockfile", *provided* PLATFORMS lists the real current platform.
    "PLATFORMS: ruby" is written here as a placeholder only -- this
    function has no way to know the sandbox container's own platform
    from the host side, and a prior attempt to rely on "ruby" alone
    turned out to be wrong: confirmed directly this Bundler version does
    NOT accept it as equivalent to an exact platform match, and instead
    triggers a real network re-resolve that the sandbox's own --network
    none isolation then blocks (see sandbox_wrapper_rubygems.py's module
    docstring for the full investigation). The real fix lives there:
    sandbox_wrapper_rubygems.py's _pin_lockfile_to_current_platform
    rewrites this placeholder to the real Gem::Platform.local, queried
    fresh from inside the exact container that will run `bundle install
    --local`, before install ever runs. "BUNDLED WITH" is omitted
    entirely -- confirmed directly a real `bundle install --local` run
    against a lockfile missing that section works identically to one
    with a (here, inevitably guessed and possibly wrong) version
    pinned."""
    specs = "\n".join(f"    {name} ({version})" for name, version in sorted(resolved_versions.items()))
    dependencies = "\n".join(f"  {name} (= {version})" for name, version in sorted(resolved_versions.items()))
    return (
        "GEM\n"
        "  remote: https://rubygems.org/\n"
        "  specs:\n"
        f"{specs}\n"
        "\n"
        "PLATFORMS\n"
        "  ruby\n"
        "\n"
        "DEPENDENCIES\n"
        f"{dependencies}\n"
    )
