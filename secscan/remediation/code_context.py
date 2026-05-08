"""Extract code/config context for a finding.

Tries to pull the relevant file snippet for findings that reference a file path.
Used by the AI enricher to give Claude meaningful context.
"""
import os
import re
from pathlib import Path


FILE_LINE_RE = re.compile(r"^(.+?):(\d+)(?::(\d+))?$")


def _parse_target(target: str) -> tuple[str, int | None]:
    """Parse 'path/to/file.py:42' or 'path/to/file.py:42:5' or just a path."""
    m = FILE_LINE_RE.match(target)
    if m:
        return m.group(1), int(m.group(2))
    return target, None


def extract_snippet(
    target: str,
    repo: str | None = None,
    context_lines: int = 8,
    max_chars: int = 2000,
) -> str | None:
    """Return a code snippet around the line referenced in target, if available.

    target: e.g. '/path/to/file.py:42' or 'src/login.py:10'
    repo: optional repo root to resolve relative paths
    """
    path, line = _parse_target(target)

    candidates = []
    if os.path.isabs(path):
        candidates.append(path)
    if repo:
        candidates.append(os.path.join(repo, path))
        candidates.append(os.path.join(repo, os.path.basename(path)))

    file_path = next((p for p in candidates if os.path.isfile(p)), None)
    if not file_path:
        return None

    try:
        with open(file_path, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return None

    if line is None:
        text = "".join(lines[:50])
        return _truncate(text, max_chars)

    start = max(0, line - 1 - context_lines)
    end = min(len(lines), line + context_lines)
    snippet_lines = []
    for i in range(start, end):
        marker = ">>>" if (i + 1) == line else "   "
        snippet_lines.append(f"{marker} {i + 1:5d} | {lines[i].rstrip()}")
    return _truncate("\n".join(snippet_lines), max_chars)


def find_config_files(repo: str | None) -> dict[str, str]:
    """Find common config files in a repo and return their contents (truncated).

    Useful for headers/CSP findings where the fix lives in a config file.
    """
    if not repo or not os.path.isdir(repo):
        return {}

    interesting = [
        "_headers", "public/_headers", "static/_headers",
        "vercel.json", "netlify.toml", "wrangler.toml",
        "next.config.js", "next.config.mjs", "next.config.ts",
        "astro.config.mjs", "astro.config.ts", "astro.config.js",
        "nginx.conf", ".htaccess",
        "package.json",
    ]
    found: dict[str, str] = {}
    for name in interesting:
        p = Path(repo) / name
        if p.is_file():
            try:
                content = p.read_text(errors="replace")
                found[name] = _truncate(content, 1500)
            except OSError:
                continue
    return found


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 20] + "\n... [truncated]"
