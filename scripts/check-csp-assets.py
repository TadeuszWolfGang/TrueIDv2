#!/usr/bin/env python3
"""Fail when web assets reintroduce CSP-blocked inline code or styles."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1] / "apps" / "web" / "assets"
HTML_PATTERNS = {
    "inline style block": re.compile(r"<style\b", re.IGNORECASE),
    "inline script block": re.compile(
        r"<script\b(?![^>]*\bsrc\s*=)[^>]*>", re.IGNORECASE | re.DOTALL
    ),
    "inline style attribute": re.compile(r"\sstyle\s*=", re.IGNORECASE),
    "inline event handler": re.compile(r"\son[a-z]+\s*=", re.IGNORECASE),
    "javascript URL": re.compile(r"javascript\s*:", re.IGNORECASE),
}
JS_PATTERNS = {
    "generated inline style attribute": re.compile(r"\bstyle\s*=", re.IGNORECASE),
    "generated inline event handler": re.compile(r"\bon[a-z]+\s*=", re.IGNORECASE),
    "cssText assignment": re.compile(r"\.cssText\b"),
    "setAttribute inline code": re.compile(
        r"\.setAttribute\(\s*['\"](?:style|on[a-z]+)['\"]", re.IGNORECASE
    ),
    "javascript URL": re.compile(r"javascript\s*:", re.IGNORECASE),
}
STYLE_PROPERTY_PATTERN = re.compile(r"\.style(?:\.([A-Za-z_$][\w$]*)|\s*\[)")
ALLOWED_STYLE_PROPERTIES = {
    Path("js/map.js"): {"left", "top"},
    Path("js/utils.js"): {"borderColor", "color"},
}


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def main() -> int:
    violations: list[str] = []
    for path in sorted(ROOT.rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        for label, pattern in HTML_PATTERNS.items():
            for match in pattern.finditer(text):
                violations.append(
                    f"{path.relative_to(ROOT)}:{line_number(text, match.start())}: {label}"
                )

    for path in sorted((ROOT / "js").glob("*.js")):
        text = path.read_text(encoding="utf-8")
        relative_path = path.relative_to(ROOT)
        for label, pattern in JS_PATTERNS.items():
            for match in pattern.finditer(text):
                violations.append(
                    f"{path.relative_to(ROOT)}:{line_number(text, match.start())}: {label}"
                )
        allowed_properties = ALLOWED_STYLE_PROPERTIES.get(relative_path, set())
        for match in STYLE_PROPERTY_PATTERN.finditer(text):
            property_name = match.group(1)
            if property_name not in allowed_properties:
                violations.append(
                    f"{relative_path}:{line_number(text, match.start())}: "
                    f"unreviewed CSSOM style mutation ({property_name or 'computed property'})"
                )

    if violations:
        for violation in violations:
            print(f"ERROR: {violation}", file=sys.stderr)
        return 1
    print("CSP asset policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
