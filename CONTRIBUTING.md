# Contributing to secscan

Thanks for considering a contribution. This document covers the practical bits: how to set up a dev environment, how the project is laid out, and what to expect during review.

## Ground rules

- Be respectful in issues and PRs. Disagreement is fine; rudeness is not.
- Security findings about secscan itself: please email gosar95@gmail.com instead of opening a public issue.
- Don't open PRs that touch hundreds of files at once. Split them.

## Dev setup

```
git clone https://github.com/Jitesh17/secscan.git
cd secscan
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/secscan --help
```

Some scanners shell out to external tools (`nuclei`, `nmap`, `subfinder`, `httpx`, `ffuf`, `semgrep`, `trivy`, `gitleaks`, `zap`). You don't need all of them to develop secscan, only the ones touching the code you're changing. `./install.sh` prints which are missing on your machine.

To enable AI-tailored remediation while developing, set `ANTHROPIC_API_KEY`:

```
export ANTHROPIC_API_KEY=sk-ant-...
```

## Project layout

```
secscan/
  cli.py            Click commands (scan, serve, list-scanners)
  runner.py         Orchestrates scanners, applies risk gating
  config.py         Defaults and per-scanner config
  dashboard.py      FastAPI dashboard
  scanners/         One file per scanner
  remediation/      Static fix DB + Claude enrichment
  reports/          HTML / Markdown / JSON renderers
  templates/        Jinja2 templates for dashboard and HTML report
```

## Adding a new scanner

1. Create `secscan/scanners/<name>.py`.
2. Subclass `Scanner` from `secscan/scanners/base.py`.
3. Set `name`, `risk` (`safe`, `low`, `medium`, `high`), and implement `run(target) -> list[Finding]`.
4. Register it in `secscan/scanners/__init__.py`.
5. If it has a typical fix, add an entry to `secscan/remediation/static_db.py`.

Keep external-tool calls behind `subprocess.run` with timeouts. Don't trust scanner output; sanitise paths and URLs before substituting them into shell commands.

## Code style

- Format with `black` and lint with `ruff` (no enforced config yet, but PRs that fight either tool will get flagged).
- Type-hint public functions. Prefer `from __future__ import annotations` at the top of new files.
- No new dependencies without a note in the PR explaining why.
- Docstrings for public functions only; comments only when the *why* is non-obvious.

## Tests

There is no test suite yet. If you fix a bug, please add at least a minimal test under `tests/` that would have caught it. Run with `pytest` once it exists.

## PR checklist

- [ ] Branch from `main`.
- [ ] One logical change per PR.
- [ ] `secscan --help` and `secscan list-scanners` still work.
- [ ] If you added a scanner, it appears in `list-scanners` output.
- [ ] If you touched packaging, `python -m build` still produces a wheel that installs cleanly.
- [ ] README updated if user-facing behaviour changed.

## Reporting a security issue

Email gosar95@gmail.com with details and a proof of concept. Please give a reasonable disclosure window before going public.
