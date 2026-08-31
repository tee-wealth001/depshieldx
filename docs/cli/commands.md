# Commands

Main commands:

- `depshieldx install`
- `depshieldx scan`
- `depshieldx uninstall`
- `depshieldx ui`
- `depshieldx doctor`
- `depshieldx routing status`
- `depshieldx routing enable`
- `depshieldx routing disable`
- `depshieldx receipts list`
- `depshieldx receipts verify <path>`
- `depshieldx receipts delete`
- `depshieldx cache clean`

Get help at any level:

```bash
depshieldx --help
depshieldx install --help
depshieldx scan --help
depshieldx uninstall --help
depshieldx ui --help
depshieldx doctor --help
depshieldx receipts --help
depshieldx cache --help
```

`depshieldx doctor` checks every prerequisite this project performs piecemeal
elsewhere -- the Python/pip version gate, Docker daemon availability, host
Trivy availability, and each ecosystem's own toolchain on `PATH` -- in one
pass, so a missing toolchain shows up before an install/scan run rather than
mid-run.

`depshieldx cache clean` reclaims disk space from the local deep-scan bundle and
provenance caches; see [Cache & Exit Codes](cache-and-exit-codes.md) for what's
cached and where.
