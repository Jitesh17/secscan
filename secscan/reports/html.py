"""HTML report writer using Jinja2."""
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from ..scanners import ScanResult
from ..config import severity_rank


_env = Environment(
    loader=PackageLoader("secscan", "templates"),
    autoescape=select_autoescape(["html"]),
)


def _duration(r: ScanResult) -> str:
    try:
        s = datetime.fromisoformat(r.started_at.replace("Z", ""))
        e = datetime.fromisoformat(r.finished_at.replace("Z", ""))
        seconds = int((e - s).total_seconds())
        if seconds < 60:
            return f"{seconds}s"
        return f"{seconds // 60}m {seconds % 60}s"
    except Exception:
        return ""


def write_html(target: str, results: list[ScanResult], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)

    sev_counts: dict[str, int] = {}
    findings = []
    for r in results:
        for f in r.findings:
            sev = (f.severity or "unknown").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            findings.append(f)
    findings.sort(key=lambda f: severity_rank(f.severity))

    summary = {
        "total_findings": sum(sev_counts.values()),
        "by_severity": dict(sorted(sev_counts.items(), key=lambda kv: severity_rank(kv[0]))),
        "scanners_run": len(results),
        "scanners_completed": sum(1 for r in results if r.status == "completed"),
    }

    enriched = []
    for r in results:
        d = r.to_dict()
        d["duration"] = _duration(r)
        enriched.append(d)

    template = _env.get_template("report.html")
    html = template.render(
        target=target,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        summary=summary,
        results=enriched,
        findings=findings,
    )
    out = output_dir / "report.html"
    out.write_text(html)
    return out
