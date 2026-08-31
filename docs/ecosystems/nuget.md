# NuGet Support

`depshieldx` can resolve, check, and install NuGet packages too, with full fast and
deep mode support.

Two ways to point it at NuGet:

**A `packages.lock.json` file in the current directory** -- auto-detected by
filename, no flag needed:

```bash
depshieldx scan --lockfile packages.lock.json
depshieldx install --lockfile packages.lock.json
```

**One or more bare package names** -- pass `--ecosystem nuget` so `depshieldx`
knows they aren't PyPI names:

```bash
depshieldx scan Newtonsoft.Json --ecosystem nuget
depshieldx install Newtonsoft.Json --ecosystem nuget
depshieldx install Newtonsoft.Json@13.0.3 --ecosystem nuget
```

A bare package name (no version) resolves to that package's latest version via
NuGet.org's search API. Resolution shells out to the real `dotnet restore` CLI against
a scratch `.csproj` in an isolated temp directory to compute the full, accurate
transitive dependency graph, the same reasoning as Cargo's/Go's/Maven's
scratch-project resolve.

If you have the [routing shim](../cli/routing.md) enabled, `dotnet add package <name>`
is also intercepted automatically and routed through
`depshieldx install <name> --ecosystem nuget` -- you don't need to change your
muscle memory.

"Install" here means `dotnet add package` -- adding the package to your
project's `.csproj`/`packages.lock.json`. Unlike Maven, `depshieldx uninstall` is
supported for NuGet, via `dotnet remove package`. Both directions are scoped to
exactly one package per invocation -- `dotnet add package`/`dotnet remove
package` themselves only ever accept a single package name.

`--deep` is supported the same way it is for PyPI, npm, Cargo, Go, and Maven: the
resolved package set (every real `.nupkg`) is fetched into a sandboxed container
(`mcr.microsoft.com/dotnet/sdk:8.0` + `strace`) and scanned with Trivy against a real,
host-generated `packages.lock.json` -- Trivy's NuGet support needs a real lock
file, it detects nothing from a bare `.csproj`. The sandboxed `dotnet build` is traced
with `strace` for filesystem, process, and network activity -- see
[Modes](../concepts/modes.md) for details. Unlike Maven's narrow annotation-processor
exception, any package shipping a `build/*.targets` or `build/*.props` file gets it
imported and evaluated during `dotnet build`, MSBuild's own general build-time
extensibility point.

Provenance checks for NuGet combine a real cryptographic checksum check (SHA-512,
verified against the exact hash NuGet.org's registration API publishes for that
release) with structural repository-signature presence -- NuGet.org has no
Sigstore/SLSA equivalent, but unlike Maven's opt-in PGP/Sigstore signing, it does
unconditionally repository-sign every package it hosts with an X.509/Authenticode
signature -- see [Provenance & Attestations](../concepts/provenance.md).

## Not supported

- `.csproj`-as-input -- only `packages.lock.json` or bare package names via
  `--ecosystem nuget` are accepted
- cryptographic chain verification of the repository signature -- `depshieldx`
  has no trust-root/certificate-chain-validation story for X.509 elsewhere, so
  presence is recorded structurally, the same way Maven's PGP-signature presence is
