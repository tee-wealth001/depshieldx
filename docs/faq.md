# FAQ

### Does it scan dependencies too?

Yes. The resolved dependency set is scanned, not just the top-level package you
typed.

### Will `install --deep` and `scan --deep` behave the same way?

Yes, except `install` performs the final host install and `scan` does not.

### What should I use most of the time?

Use:

```bash
depshieldx install <package>
```

Use `--deep` when you want the extra Docker + Trivy validation step.
