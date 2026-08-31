# Receipts

Every completed install or scan attempts to write signed local receipt JSON files.

Important receipt behavior:

- single-package runs produce one receipt
- multi-package runs produce one receipt per requested package
- requirements, lockfile, and `pyproject.toml` runs also write per-requested-package
  receipts when possible

## Receipt commands

```bash
depshieldx receipts list
depshieldx receipts verify ~/.depshieldx-cache/receipts/<receipt>.json
depshieldx receipts delete
```

Receipts include package-level details such as:

- package and resolved version
- project link
- provenance summary
- scan summary
- historical/fixed CVE entries for that package
