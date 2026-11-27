#!/usr/bin/env python3
"""Check relative links in the repository's Markdown files.

For every tracked *.md file: each inline link [text](target) and each
reference definition [label]: target that is not an absolute URL must point
at an existing file or directory, and a #fragment must match a heading of
the target file (GitHub's anchor rules, approximated).

With --backticks, paths written in backticks are checked too when they
start with a top-level directory of this repository, since many
cross-references in these docs are written that way. Patterns (`*`, `<…>`)
and build outputs (`.generated/`, `dist/`) are skipped.

Usage: scripts/check-links.py [--backticks]     exit 0 = nothing broken
No network access: http(s) and mailto links are not checked.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INLINE = re.compile(r"\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REFDEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?\s*$")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
BACKTICK = re.compile(r"`([A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-*<>…]+)+/?)`")
TOP = ("attest-sidecar/", "common/", "demo/", "deploy/", "docs/", "policy/",
       "scripts/", "verifier/", "web/", ".github/")
# Backticked paths that name files in the upstream dstack repository, not here.
UPSTREAM = {
    "docs/deployment.md", "docs/hardware-enablement.md",
    "docs/tutorials/tdx-bios-configuration.md",
    "docs/tutorials/tdx-hardware-verification.md",
    "docs/tutorials/tdx-sgx-verification.md", "docs/building-guest-os.md",
    "docs/encrypted-env-spec.md",
}


def md_files():
    out = subprocess.run(["git", "ls-files", "--cached", "--others",
                          "--exclude-standard", "*.md"],
                         cwd=ROOT, check=True, capture_output=True, text=True)
    return sorted(f for f in out.stdout.split("\n") if f)


def outside_code(lines):
    """Yield (lineno, text) for lines outside fenced code blocks."""
    fence = None
    for n, line in enumerate(lines, 1):
        s = line.lstrip()
        if fence is None and (s.startswith("```") or s.startswith("~~~")):
            fence = s[:3]
            continue
        if fence is not None:
            if s.startswith(fence):
                fence = None
            continue
        yield n, line


def slug(text):
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)   # links -> text
    text = text.replace("`", "").replace("*", "").strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def anchors(path, cache={}):
    if path not in cache:
        seen, out = {}, set()
        with open(path, encoding="utf-8") as fh:
            for _, line in outside_code(fh.read().split("\n")):
                m = HEADING.match(line)
                if not m:
                    continue
                s = slug(m.group(2))
                k = seen.get(s, 0)
                seen[s] = k + 1
                out.add(s if k == 0 else f"{s}-{k}")
        cache[path] = out
    return cache[path]


def main():
    backticks = "--backticks" in sys.argv[1:]
    files = md_files()
    broken, checked = [], 0
    for rel in files:
        src = os.path.join(ROOT, rel)
        with open(src, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        for n, line in outside_code(lines):
            targets = INLINE.findall(line)
            m = REFDEF.match(line)
            if m:
                targets.append(m.group(1))
            for t in targets:
                if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:", t):
                    continue                      # http:, https:, mailto:
                checked += 1
                path, _, frag = t.partition("#")
                dest = src if not path else os.path.normpath(
                    os.path.join(os.path.dirname(src), path))
                if not os.path.exists(dest):
                    broken.append(f"{rel}:{n}: {t}  (no such file)")
                elif (frag and dest.endswith(".md")
                      and frag.lower() not in anchors(dest)):
                    broken.append(f"{rel}:{n}: {t}  (no such heading)")
            if not backticks:
                continue
            for t in BACKTICK.findall(INLINE.sub("", line)):
                if (not t.startswith(TOP) or t in UPSTREAM
                        or any(c in t for c in "*<>…")
                        or ".generated" in t or "/dist" in t):
                    continue
                checked += 1
                here = os.path.normpath(os.path.join(os.path.dirname(src), t))
                if not (os.path.exists(os.path.join(ROOT, t))
                        or os.path.exists(here)):
                    broken.append(f"{rel}:{n}: `{t}`  (no such path)")
    for b in broken:
        print(b)
    print(f"{checked} relative link(s) checked in {len(files)} file(s); "
          f"{len(broken)} broken")
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
