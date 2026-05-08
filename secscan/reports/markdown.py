"""Markdown report writer."""
from datetime import datetime
from pathlib import Path

from ..scanners import ScanResult
from ..config import severity_rank


SEV_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
    "unknown": "⚫",
}


def write_markdown(target: str, results: list[ScanResult], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append(f"# Security scan report: {target}")
    lines.append("")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z")
    lines.append("")

    sev_counts: dict[str, int] = {}
    all_findings = []
    for r in results:
        for f in r.findings:
            sev = (f.severity or "unknown").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            all_findings.append(f)

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in sorted(sev_counts, key=severity_rank):
        emoji = SEV_EMOJI.get(sev, "")
        lines.append(f"| {emoji} {sev.title()} | {sev_counts[sev]} |")
    lines.append("")

    lines.append("## Scanner status")
    lines.append("")
    lines.append("| Scanner | Status | Findings | Notes |")
    lines.append("|---|---|---|---|")
    for r in sorted(results, key=lambda x: x.scanner):
        notes = r.error if r.error else ""
        lines.append(f"| `{r.scanner}` | {r.status} | {len(r.findings)} | {notes} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    all_findings.sort(key=lambda f: severity_rank(f.severity))
    for i, f in enumerate(all_findings, 1):
        emoji = SEV_EMOJI.get(f.severity.lower(), "")
        lines.append(f"### {i}. {emoji} {f.title}")
        lines.append("")
        lines.append(f"**Severity:** {f.severity}  ")
        lines.append(f"**Scanner:** `{f.scanner}`  ")
        lines.append(f"**Target:** `{f.target}`")
        lines.append("")
        if f.description:
            lines.append(f.description)
            lines.append("")
        if f.evidence:
            lines.append("**Evidence:**")
            lines.append("```")
            lines.append(f.evidence[:1000])
            lines.append("```")
            lines.append("")
        if f.remediation:
            lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")
        if f.raw.get("static_rationale"):
            lines.append(f"> **Why it matters:** {f.raw['static_rationale']}")
            lines.append("")
        if f.raw.get("static_example"):
            lines.append("**Example fix:**")
            lines.append("```")
            lines.append(f.raw["static_example"])
            lines.append("```")
            lines.append("")
        if f.raw.get("ai_fix"):
            confidence = f.raw.get("ai_confidence", "")
            lines.append(f"**🤖 AI suggestion** "
                         f"({'confidence: ' + confidence if confidence else 'tailored fix'}):")
            lines.append("")
            lines.append(f.raw["ai_fix"])
            lines.append("")
            if f.raw.get("ai_rationale"):
                lines.append(f"_{f.raw['ai_rationale']}_")
                lines.append("")
            if f.raw.get("ai_example"):
                lines.append("```")
                lines.append(f.raw["ai_example"])
                lines.append("```")
                lines.append("")
        if f.references:
            lines.append("**References:**")
            for ref in f.references:
                if ref:
                    lines.append(f"- {ref}")
            lines.append("")

    out = output_dir / "report.md"
    out.write_text("\n".join(lines))
    return out
