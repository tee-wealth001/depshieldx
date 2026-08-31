# Output & Summary

## Output modes

Human-readable summary:

```bash
depshieldx install requests --output summary
```

JSON only:

```bash
depshieldx install requests --output json
```

Summary plus JSON:

```bash
depshieldx install requests --output both
depshieldx install requests --full-report
```

## What the summary means

Key summary lines:

- `Scan verdict`
- `CVE sources across all resolved packages`
- `Provenance verdict`
- `Attestation verification`
- `Sandbox verdict`
- `Trivy verdict`
- `Host install`
- `Receipts`

`Scan verdict` reflects the resolved package set, including dependencies.

`Provenance verdict` means the provenance checks did or did not block. A package can
still pass provenance and show informational items such as:

- missing author or maintainer email
- missing PyPI attestations

That is expected. `passed` means "not blocked", not "perfect metadata".

`Attestation verification` describes how many attested selected files verified
successfully. It does not mean every package had attestations.

`historical/fixed` CVEs mean the source knows about past vulnerabilities in the
package history, but not in the exact versions currently selected for install.

### Example summary

```text
Summary
Package: fastapi
Mode: fast
Install target: fastapi==0.135.2
Resolved packages: 10
Scan verdict: passed with 0 warning(s), 0 info item(s)
CVE sources across all resolved packages:
  • cisa-kev: no vulnerabilities
  • deps-dev: 0 advisories, 10 package record(s) checked
  • github-advisories: no vulnerabilities
  • osv: 0 affecting resolved version(s), 15 historical/fixed entries in resolved dependency history
Provenance verdict: passed with 0 warning(s), 0 info item(s)
Attestation verification: 7/7 attested file(s) verified, available
Host install: succeeded (fastapi==0.135.2, https://pypi.org/project/fastapi/0.135.2/)
Receipts: allowed (1 package receipt)
Receipt ID: abc123def4567890
Receipt path:
  - /Users/you/.depshieldx-cache/receipts/20260331T000000Z-fastapi-0.135.2-abc123def4567890.json
```

For multi-package installs, the summary also includes:

- a requested-package source breakdown
- one receipt path per requested package
- one project link (PyPI, npm, crates.io, pkg.go.dev, nuget.org, pub.dev,
  rubygems.org, or packagist.org) per requested package when relevant
