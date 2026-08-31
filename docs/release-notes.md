# Release Notes

For a release build:

- confirm the included Apache 2.0 license still matches how you want to distribute
  the project
- build and verify distributions in a Python `3.11.4+` environment
- run `python -m build`
- run `python -m twine check dist/*`
- for TestPyPI, run the `Release Checks` workflow manually
- for PyPI, push a version tag such as `v0.1.0` &mdash; this also triggers the
  `Release Binaries` workflow, which builds and attaches the standalone
  per-platform binaries to the matching GitHub Release

See the [GitHub Releases page](https://github.com/tee-wealth001/depshieldx/releases)
for the full version history and changelogs.
