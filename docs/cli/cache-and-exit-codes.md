# Cache & Exit Codes

## Cache location

By default, local state lives under:

```text
~/.depshieldx-cache
```

That directory can contain:

- provenance cache entries
- deep-scan cache entries
- receipts
- routing state

You can inspect those cached results in the local browser UI with:

```bash
depshieldx ui
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | success |
| `10` | blocked by resolution, provenance, vulnerability checks, or Trivy |
| `11` | deep mode could not use Docker and the install or scan was skipped for that reason |
| `12` | host install was attempted but failed |
