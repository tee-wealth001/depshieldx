# Quick Start

Install with the default path:

```bash
depshieldx install requests
```

Run the deeper validation path:

```bash
depshieldx install requests --deep
```

Scan without installing:

```bash
depshieldx scan requests
```

Scan a requirements file:

```bash
depshieldx scan -r requirements.txt
```

Install from `pyproject.toml`:

```bash
depshieldx install --pyproject pyproject.toml
```

## Common examples

Install one package:

```bash
depshieldx install fastapi
```

Install multiple packages:

```bash
depshieldx install langchain requests --deep
```

Scan only:

```bash
depshieldx scan fastapi --fast
depshieldx scan fastapi --deep
```

Use a requirements file:

```bash
depshieldx install -r requirements.txt
depshieldx scan -r requirements.txt --deep
```

Use a lockfile:

```bash
depshieldx install --lockfile uv.lock
depshieldx scan --lockfile uv.lock
```

Use a `pyproject.toml` file:

```bash
depshieldx install --pyproject pyproject.toml
depshieldx scan --pyproject pyproject.toml --deep
```

Open the local cache UI:

```bash
depshieldx ui
depshieldx ui --port 8765
depshieldx ui --no-open
```

Uninstall packages:

```bash
depshieldx uninstall requests
depshieldx uninstall -r requirements.txt
depshieldx uninstall --pyproject pyproject.toml
```

## Other ecosystems

Each ecosystem has its own bare-name and lockfile examples on its own page &mdash; see
the [ecosystems overview](../ecosystems/index.md), or jump to the full command list on
the [Examples](../examples.md) page.
