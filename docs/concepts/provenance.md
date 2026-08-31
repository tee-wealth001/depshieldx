# Provenance & Attestations

The provenance stage checks the exact artifacts selected for your environment, not
every file on the release page.

A block only happens when verification was actually attempted and failed -- not
attestations being absent, since most packages on PyPI and npm don't publish them,
Cargo/Go have no per-package attestations to check in the first place, most Maven
artifacts published today are PGP-only, not yet Sigstore-signed, and Pub/RubyGems/
Composer have no default signing scheme to check in the first place either.

=== "PyPI"

    - whether the release exists on PyPI
    - whether the release is source-only
    - whether the release is a pre-release
    - whether homepage/project URLs exist
    - whether author or maintainer email metadata exists
    - whether the selected files have PyPI attestations
    - whether those attestations verify successfully (a real Sigstore bundle check,
      not just presence)

=== "npm / yarn / pnpm"

    - whether the release is deprecated
    - whether homepage/repository and author/maintainer metadata exist
    - whether the resolved release has an integrity digest
    - whether the release has npm provenance attestations, and whether its SLSA
      provenance attestation (the one signed via GitHub Actions OIDC through a real
      Fulcio certificate) verifies successfully -- npm's separate "publish"
      attestation, signed with npm registry's own key rather than a Fulcio
      certificate, is recorded but not cryptographically verified here, since that's
      a different trust model

=== "Cargo"

    There is no cryptographic attestation infrastructure to check against --
    crates.io does not support Sigstore/SLSA provenance the way PyPI and npm do.
    Instead, `depshieldx` checks:

    - whether the resolved version has been yanked
    - whether homepage/repository metadata exists
    - crates.io's self-reported Trusted Publishing metadata (provider, repository,
      run ID), where present -- recorded for reference only, since crates.io
      does not sign or publish a verifiable attestation for it

=== "Go"

    Checksum verification against the real checksum-transparency log
    (sum.golang.org, a cryptographically-signed Merkle tree) already happens
    transparently inside the `go` toolchain itself during resolution -- there's
    no separate per-package attestation to verify the way PyPI/npm have. Instead,
    `depshieldx` checks:

    - whether the resolved version has been retracted (a module author publishing a
      later version that lists a prior one as retracted -- Go's closest
      equivalent to a yanked release)
    - basic module metadata

=== "Maven"

    Provenance combines a checksum with structural and (where available) real
    cryptographic signals:

    - checksum verification (SHA-256 where Central publishes one, falling back to
      SHA-1 for older releases -- MD5 is never trusted)
    - whether the resolved artifact has a PGP signature (Central has required these
      since the 2010s) -- presence is recorded structurally only, since there's
      no central root of trust binding an arbitrary PGP key to a real-world identity
      the way Sigstore's Fulcio certificates are
    - whether the resolved artifact has a Sigstore bundle and, if so, whether it
      verifies successfully (a real cryptographic check, not just presence) --
      supported by Maven Central's Publisher Portal since January 2025, but still new
      and opt-in; most published artifacts don't have one yet

=== "NuGet"

    Provenance combines a real cryptographic checksum check with structural
    signature-presence:

    - checksum verification (SHA-512, verified against the exact hash NuGet.org's own
      registration API publishes for that release)
    - whether the resolved package has a repository signature -- NuGet.org
      unconditionally repository-signs every package it hosts with an
      X.509/Authenticode signature, so presence is checked directly against the
      `.nupkg`'s own signature entry, but the certificate chain itself is not
      cryptographically validated
    - whether the resolved version is unlisted (NuGet's structural yank-equivalent)
      or marked deprecated

=== "Pub"

    Provenance combines a real cryptographic checksum check with structural signals
    -- pub.dev has no signing scheme of its own at all:

    - checksum verification (SHA-256, verified against the exact hash pub.dev's own
      package API publishes for that release)
    - whether the resolved package is discontinued (a real, package-level flag an
      author or pub.dev admin can set, optionally naming a replacement)
    - whether the resolved version has been retracted (a publisher can retract a
      version within 7 days of publishing it)

=== "RubyGems"

    Provenance combines a real cryptographic checksum check with a structural yank
    signal -- rubygems.org has no default, always-present signing scheme either
    (Sigstore support is still opt-in/in-progress, the older X.509 `gem cert` scheme
    is opt-in and rarely used):

    - checksum verification (SHA-256, verified against the exact hash rubygems.org's
      own API publishes for that release)
    - whether the resolved version has been yanked, where the registry still reports
      it (a version yanked long enough ago is fully removed from the registry
      instead of staying queryable with a `yanked: true` flag -- confirmed
      against the real 2019 `rest-client` hijack incident, versions 1.6.10-1.6.13:
      both the full versions list and the per-version registry endpoint have no
      record of it at all, a plain 404 rather than a `yanked: true` payload. Since
      that 404 is genuinely ambiguous between "never existed" and "yanked and
      purged", `depshieldx` surfaces it as an honest, non-blocking "could not verify
      this version" warning rather than asserting a specific cause it can't
      actually confirm)

=== "Composer"

    Provenance is structural more often than cryptographic -- Packagist has no
    signing scheme of its own at all, and most packages don't even publish a
    checksum to fall back on:

    - checksum verification when Packagist's `dist.shasum` is actually published for
      the resolved version (a real SHA-1 hash comparison) -- this is empty for
      essentially every real package, so the common case is an honest "no checksum
      published, pinned by git reference only" info note instead of a check
    - the git commit `reference` Packagist records for the resolved dist archive
      -- the one real, always-present content pin regardless of whether a
      checksum is published
    - whether the package is `abandoned` (a real, package-level flag that can be a
      plain boolean or a string naming a suggested replacement)
