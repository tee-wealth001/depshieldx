# Go Modules Support

`depshieldx` can resolve, check, and install Go modules too, with full fast and deep
mode support.

Two ways to point it at Go:

**A `go.sum` file in the current directory** &mdash; auto-detected by filename, no
flag needed:

```bash
depshieldx scan --lockfile go.sum
depshieldx install --lockfile go.sum
```

**One or more bare module paths** &mdash; pass `--ecosystem go` so `depshieldx` knows
they aren't PyPI names:

```bash
depshieldx scan github.com/pkg/errors --ecosystem go
depshieldx install github.com/pkg/errors --ecosystem go
depshieldx install github.com/pkg/errors golang.org/x/text --ecosystem go
```

Bare module-path resolution shells out to the real `go get` CLI against a scratch
module in an isolated temp directory to compute the full, accurate resolved module
graph &mdash; `go.sum` alone can't reconstruct it, since it's a checksum allowlist (it
can list more versions of a module than actually ship, every version Minimal Version
Selection considered, not just the winner), not the resolved graph itself.
`--lockfile go.sum` resolution reads the sibling `go.mod`'s directory the same way,
via `go list -m all`.

If you have the [routing shim](../cli/routing.md) enabled, `go get <module>` is also
intercepted automatically and routed through
`depshieldx install <module> --ecosystem go` &mdash; you don't need to change your
muscle memory.

"Install" here means `go get` &mdash; adding the module(s) to your project's
`go.mod`/`go.sum` &mdash; not `go install` (installing a binary program; since Go
1.18, `go get` itself never builds or installs anything). `depshieldx` does not
currently support installing binary programs.

`--deep` is supported the same way it is for PyPI, npm, and Cargo: the resolved
module set is fetched into a sandboxed container (`golang:1-bookworm` + `strace`) via
a local file-based Go module proxy built on the host, and scanned with Trivy &mdash;
Trivy reads `go.mod`/`go.sum` natively, needing no extracted source tree the way
Cargo's vendor directory does. The sandboxed `go build` is traced with `strace` for
filesystem, process, and network activity &mdash; see [Modes](../concepts/modes.md)
for details. Not every resolved module has an importable root package (some are
subpackage-only, like `golang.org/x/crypto`); those are gracefully skipped from
behavioral tracing rather than failing the whole build, and recorded as skipped in the
full JSON report. `depshieldx uninstall` is also supported, via `go get <module>@none`.

Provenance checks for Go are structural only, not cryptographic: crates.io-style
attestation infrastructure doesn't exist for Go modules either. Checksum verification
against Go's real checksum-transparency log (sum.golang.org) already happens
transparently inside the `go` toolchain itself during resolution &mdash; what
`depshieldx` checks independently is the `retract` directive (a module author
retracting a previously published version), the closest Go equivalent to PyPI's/
Cargo's yanked-release signal &mdash; see
[Provenance & Attestations](../concepts/provenance.md).

## Not supported

- installing binary programs (`go install`) &mdash; `depshieldx`'s Go support only
  covers dependency modules added via `go get`
- `go.mod`-as-input &mdash; only `go.sum` or bare module paths via `--ecosystem go`
  are accepted
- cryptographic provenance verification of the kind PyPI/npm have (per-package
  Sigstore signing) &mdash; Go's real checksum-transparency verification already
  happens inside the `go` toolchain itself, not as a separate `depshieldx`-driven step
