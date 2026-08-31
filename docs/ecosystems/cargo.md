# Cargo / crates.io Support

`depshieldx` can resolve, check, and install Cargo crates too, with full fast and deep
mode support.

Two ways to point it at Cargo:

**A `Cargo.lock` file in the current directory** -- auto-detected by filename, no
flag needed:

```bash
depshieldx scan --lockfile Cargo.lock
depshieldx install --lockfile Cargo.lock
```

**One or more bare crate names** -- pass `--ecosystem cargo` so `depshieldx`
knows they aren't PyPI names:

```bash
depshieldx scan serde --ecosystem cargo
depshieldx install serde --ecosystem cargo
depshieldx install serde tokio --ecosystem cargo
```

Bare crate-name resolution shells out to the real `cargo add` CLI against a scratch
package in an isolated temp directory to compute the full, accurate resolved
dependency set, then checks that whole resolved set before installing.

If you have the [routing shim](../cli/routing.md) enabled, `cargo add <crate>` is also
intercepted automatically and routed through
`depshieldx install <crate> --ecosystem cargo` -- you don't need to change your
muscle memory.

"Install" here means `cargo add` -- adding the crate(s) to your project's
`Cargo.toml`/`Cargo.lock` -- not `cargo install` (installing a binary crate).
`depshieldx` does not currently support installing binary crates.

`--deep` is supported the same way it is for PyPI and npm: the resolved crate set is
fetched into a sandboxed container (`rust:1-slim` + `strace`) and scanned with Trivy,
and the sandboxed `cargo build --offline` is traced with `strace` for filesystem,
process, and network activity -- see [Modes](../concepts/modes.md) for details.
`depshieldx uninstall` is also supported, via `cargo remove`.

Provenance checks for Cargo are structural only, not cryptographic: crates.io has no
Sigstore/SLSA attestation infrastructure to verify against, unlike PyPI and npm.
Checks are limited to things like yanked-release status and registry metadata --
see [Provenance & Attestations](../concepts/provenance.md).

## Not supported

- installing binary crates (`cargo install`) -- `depshieldx`'s Cargo support only
  covers dependency crates added via `cargo add`
- `Cargo.toml`-as-input -- only `Cargo.lock` or bare crate names via
  `--ecosystem cargo` are accepted
- cryptographic provenance verification -- crates.io has nothing to verify
  against
