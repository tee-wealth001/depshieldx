---
title: depshieldx
---

<div class="hero" markdown>

# depshieldx

<p class="tagline">
A safer wrapper around package install and scan workflows &mdash; for PyPI, npm/yarn/pnpm,
Cargo/crates.io, Go modules, Maven/Maven Central, NuGet/NuGet.org, Pub/pub.dev,
RubyGems/rubygems.org, and Composer/Packagist.
</p>

[Get Started](getting-started/installation.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/tee-wealth001/depshieldx){ .md-button }

</div>

[![PyPI version](https://img.shields.io/pypi/v/depshieldx.svg)](https://pypi.org/project/depshieldx/)

Before installing, `depshieldx` resolves the full package set, checks provenance for the
exact artifacts that would be used, queries four vulnerability sources for the resolved
versions, and can optionally run a deeper Docker + Trivy validation path with real
behavioral tracing of the sandboxed install. Every completed install or scan also writes
signed local receipt JSON files.

## What it does

<div class="grid cards" markdown>

-   :material-source-branch-check:{ .lg .middle } **Full dependency resolution**

    ---

    Resolves the complete dependency set before installation, across all nine
    supported ecosystems.

-   :material-certificate:{ .lg .middle } **Provenance checks**

    ---

    Verifies the exact release artifacts that would be used &mdash; cryptographic
    Sigstore verification on PyPI/npm/Maven, checksum + structural checks elsewhere.

    [:octicons-arrow-right-24: Provenance & Attestations](concepts/provenance.md)

-   :material-shield-search:{ .lg .middle } **Four vulnerability sources**

    ---

    Queries OSV, GitHub Advisories, CISA KEV, and deps.dev concurrently for every
    resolved package version.

    [:octicons-arrow-right-24: Vulnerability Sources](concepts/vulnerability-sources.md)

-   :material-docker:{ .lg .middle } **Deep mode**

    ---

    Docker + Trivy scanning with real syscall-level behavioral tracing of the
    sandboxed install, for every supported ecosystem.

    [:octicons-arrow-right-24: Modes](concepts/modes.md)

-   :material-file-sign:{ .lg .middle } **Signed receipts**

    ---

    Every completed install or scan writes a signed local receipt JSON file you can
    list, verify, and inspect later.

    [:octicons-arrow-right-24: Receipts](concepts/receipts.md)

-   :material-source-repository:{ .lg .middle } **Nine ecosystems**

    ---

    PyPI, npm/yarn/pnpm, Cargo, Go modules, Maven, NuGet, Pub, RubyGems, and Composer,
    each with ecosystem-specific provenance and tracing support.

    [:octicons-arrow-right-24: Ecosystems overview](ecosystems/index.md)

</div>

## Quick start

Install with the default (fast) path:

```bash
depshieldx install requests
```

Run the deeper Docker + Trivy validation path:

```bash
depshieldx install requests --deep
```

Scan without installing:

```bash
depshieldx scan requests
```

See [Quick Start](getting-started/quickstart.md) for more, including lockfiles,
`pyproject.toml`, and other ecosystems.

## Project links

- PyPI: [pypi.org/project/depshieldx](https://pypi.org/project/depshieldx/)
- Source: [github.com/tee-wealth001/depshieldx](https://github.com/tee-wealth001/depshieldx)
- Issues: [github.com/tee-wealth001/depshieldx/issues](https://github.com/tee-wealth001/depshieldx/issues)
