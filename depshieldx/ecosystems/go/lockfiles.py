"""Parser for `go list -m -json all` output -- Go's authoritative resolved
module graph (Minimal Version Selection already applied), not go.sum.

go.sum is a checksum allowlist, not a resolved dependency graph: it records
a hash for every module version considered anywhere during resolution,
including versions later superseded by a higher requirement elsewhere in
the graph -- confirmed directly by resolving a real multi-dependency module
and inspecting the go.sum produced, which listed more version entries than
modules in the actual build list. Cargo.lock's "newest version wins"
tie-break (see cargo_lockfiles.py) would therefore give an actively wrong
answer for Go: Minimal Version Selection deliberately does not always pick
the newest available version. The real resolved set is whatever `go list -m
all` reports, mirroring why CargoEcosystem/NpmEcosystem shell out to their
own tool's resolver rather than reimplementing it -- this applies even more
strongly here, since go.sum alone can't even reconstruct the answer.
"""

import json


def parse_go_list_module_output(raw_text: str) -> dict[str, str]:
    """`go list -m -json all` prints a stream of concatenated JSON objects
    (confirmed directly -- not a JSON array, so json.loads() on the whole
    text fails). Skips the main module itself (Main: true) and any module
    with no Version (a local `replace` directive pointing at a filesystem
    path has none -- confirmed directly against a real `replace` entry)."""
    decoder = json.JSONDecoder()
    resolved: dict[str, str] = {}
    index = 0
    length = len(raw_text)
    while index < length:
        while index < length and raw_text[index] in " \t\r\n":
            index += 1
        if index >= length:
            break
        entry, end_index = decoder.raw_decode(raw_text, index)
        index = end_index
        if entry.get("Main"):
            continue
        path = entry.get("Path")
        version = entry.get("Version")
        if not path or not version:
            continue
        resolved[path] = version
    return resolved
