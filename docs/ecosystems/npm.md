# npm / yarn / pnpm Support

`depshieldx` can resolve, check, and install npm packages too, with full fast and deep
mode support.

Two ways to point it at npm:

**A lockfile in the current directory** &mdash; auto-detected by filename, no flag
needed:

```bash
depshieldx scan --lockfile package-lock.json
depshieldx scan --lockfile yarn.lock
depshieldx scan --lockfile pnpm-lock.yaml
depshieldx install --lockfile package-lock.json
```

**One or more bare package names** &mdash; pass `--ecosystem npm` so `depshieldx`
knows they aren't PyPI names:

```bash
depshieldx scan left-pad --ecosystem npm
depshieldx install left-pad --ecosystem npm
depshieldx install left-pad is-odd --ecosystem npm
```

Bare package-name resolution shells out to the real `npm` CLI in an isolated temp
directory to compute the full, accurate transitive dependency tree, then checks that
whole resolved set before installing. Installing pins each requested package to the
exact version that was just checked (`npm install left-pad@1.3.0`), not a floating
range, so nothing can drift to a different release between the scan and the install.

If you have the [routing shim](../cli/routing.md) enabled, `npm install <package>` is
also intercepted automatically and routed through
`depshieldx install <package> --ecosystem npm` &mdash; you don't need to change your
muscle memory.

npm/yarn/pnpm has full functional parity with PyPI: `--deep` (Docker + Trivy + real
behavioral tracing via strace), `depshieldx uninstall`, and cryptographic provenance
verification (real Sigstore bundle verification of npm's SLSA provenance attestations,
not just presence checks &mdash; see [Provenance & Attestations](../concepts/provenance.md))
are all supported.

## Not supported

- `requirements.txt`/`pyproject.toml`-style inputs &mdash; those formats are
  inherently PyPI-specific; use a lockfile or `--ecosystem npm` instead
