# Local UI

`depshieldx ui` opens a local browser view over cached receipts and related cache
entries &mdash; mostly read-only, with one exception: each receipt row has a delete
button to remove that one receipt.

- binds to `127.0.0.1` only
- uses port `0` by default so the OS can choose a free port
- opens the browser automatically unless you pass `--no-open`

Examples:

```bash
depshieldx ui
depshieldx ui --port 8765
depshieldx ui --no-open
```
