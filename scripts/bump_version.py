#!/usr/bin/env python3
"""Bump the misp-mcp version everywhere in one command.

    python scripts/bump_version.py 1.1.0

`misp_mcp/__init__.py` is the single source of truth: pyproject reads it
dynamically, and `misp-mcp --version` / misp_instance_status read it at
runtime. This script also updates the one *static* display surface that
cannot read it on its own — the README version badge — so it never drifts.
(The banner images are intentionally version-free.) It does not commit, tag,
or edit the changelog; it prints those as the next steps.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def replace_once(path: Path, pattern: str, repl: str) -> bool:
    text = path.read_text()
    new, n = re.subn(pattern, repl, text)
    if n:
        path.write_text(new)
    return bool(n)


def main() -> int:
    if len(sys.argv) != 2 or not SEMVER.match(sys.argv[1]):
        print("usage: python scripts/bump_version.py <major.minor.patch>", file=sys.stderr)
        return 2
    new = sys.argv[1]

    init = ROOT / "misp_mcp" / "__init__.py"
    old_m = re.search(r'__version__\s*=\s*"([^"]+)"', init.read_text())
    old = old_m.group(1) if old_m else "?"

    changed = []
    if replace_once(init, r'__version__\s*=\s*"[^"]+"', f'__version__ = "{new}"'):
        changed.append(str(init.relative_to(ROOT)))
    if replace_once(ROOT / "README.md", r"version-\d+\.\d+\.\d+-", f"version-{new}-"):
        changed.append("README.md")

    print(f"bumped {old} -> {new}")
    for c in changed:
        print(f"  updated {c}")
    print("\nnext steps:")
    print(f"  1. add a '## [{new}]' section to CHANGELOG.md")
    print(f"  2. commit, then tag:  git tag v{new} && git push --tags")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
