"""JSON report writer."""
import json
from datetime import datetime
from pathlib import Path

from ..scanners import ScanResult
from ..config import severity_rank


def write_json(target: str, results: list[ScanResult], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "target": target,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": _summarize(results),
        "results": [r.to_dict() for r in results],
    }
    out = output_dir / "report.json"
    out.write_text(json.dumps(payload, indent=2, default=str))
    return out


def _summarize(results: list[ScanResult]) -> dict:
    sev_counts: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            sev = (f.severity or "unknown").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
    return {
        "total_findings": sum(sev_counts.values()),
        "by_severity": dict(sorted(
            sev_counts.items(),
            key=lambda kv: severity_rank(kv[0]),
        )),
        "scanners_run": len(results),
        "scanners_completed": sum(1 for r in results if r.status == "completed"),
        "scanners_skipped": sum(1 for r in results if r.status == "skipped"),
        "scanners_errored": sum(1 for r in results if r.status in ("error", "timeout")),
    }
