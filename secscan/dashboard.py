"""FastAPI dashboard. Single-page UI for triggering scans and viewing reports."""
import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
from jinja2 import PackageLoader, Environment, select_autoescape

from .config import SCANNERS, PROFILES, Risk
from .runner import run_scans
from .reports import write_html, write_markdown, write_json


app = FastAPI(title="secscan dashboard")
templates_env = Environment(
    loader=PackageLoader("secscan", "templates"),
    autoescape=select_autoescape(["html"]),
)

REPORTS_ROOT = Path("./reports").resolve()
REPORTS_ROOT.mkdir(parents=True, exist_ok=True)

JOBS: dict[str, dict[str, Any]] = {}


@app.get("/", response_class=HTMLResponse)
async def index():
    template = templates_env.get_template("dashboard.html")
    scanners = []
    for name, info in SCANNERS.items():
        scanners.append({
            "name": name,
            "title": info.name,
            "description": info.description,
            "risk": info.risk.value,
            "tool": info.requires_tool or "builtin",
            "damage": info.damage_estimate,
        })
    return template.render(
        scanners=scanners,
        profiles=PROFILES,
    )


@app.post("/api/scan")
async def start_scan(payload: dict):
    target = payload.get("target", "").strip()
    scanner_names = payload.get("scanners", [])
    repo = payload.get("repo") or None
    enrich = payload.get("enrich", True)
    use_ai = payload.get("ai", True)
    include_code = payload.get("include_code", True)

    if not target:
        raise HTTPException(400, "target is required")
    if "://" not in target:
        target = "https://" + target
    if not scanner_names:
        raise HTTPException(400, "select at least one scanner")

    invalid = [s for s in scanner_names if s not in SCANNERS]
    if invalid:
        raise HTTPException(400, f"unknown scanners: {invalid}")

    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {
        "id": job_id,
        "target": target,
        "scanners": scanner_names,
        "status": "running",
        "events": [],
        "started_at": datetime.utcnow().isoformat(),
        "report_dir": None,
    }

    options = {
        "repo": repo,
        "enrich": enrich,
        "ai": use_ai,
        "include_code": include_code,
    }
    asyncio.create_task(_run_job(job_id, target, scanner_names, options))
    return {"job_id": job_id}


async def _run_job(job_id: str, target: str, scanner_names: list[str], options: dict):
    job = JOBS[job_id]
    loop = asyncio.get_event_loop()

    def on_complete(res):
        job["events"].append({
            "scanner": res.scanner,
            "status": res.status,
            "findings": len(res.findings),
            "error": res.error,
        })

    try:
        results = await loop.run_in_executor(
            None,
            lambda: run_scans(
                target=target,
                scanner_names=scanner_names,
                options=options,
                max_workers=4,
                on_complete=on_complete,
            ),
        )

        if options.get("enrich", True):
            from .remediation import enrich_findings, build_config_from_env
            all_findings = [f for r in results for f in r.findings]
            if all_findings:
                cfg = build_config_from_env(
                    enable_ai=options.get("ai", True),
                    include_code=options.get("include_code", True),
                    repo=options.get("repo"),
                )
                job["events"].append({
                    "scanner": "_enrichment",
                    "status": "running",
                    "findings": len(all_findings),
                    "error": "",
                })
                await loop.run_in_executor(
                    None,
                    lambda: enrich_findings(all_findings, cfg),
                )
                job["events"].append({
                    "scanner": "_enrichment",
                    "status": "completed",
                    "findings": len(all_findings),
                    "error": "AI on" if cfg.enabled else "static only",
                })

        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        safe = target.replace("https://", "").replace("http://", "").replace("/", "_")
        run_dir = REPORTS_ROOT / f"{safe}-{timestamp}"
        write_html(target, results, run_dir)
        write_markdown(target, results, run_dir)
        write_json(target, results, run_dir)
        job["report_dir"] = run_dir.name
        job["status"] = "completed"
    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
    finally:
        job["finished_at"] = datetime.utcnow().isoformat()


@app.get("/api/jobs/{job_id}")
async def job_status(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(404, "job not found")
    return JOBS[job_id]


@app.get("/api/reports")
async def list_reports():
    if not REPORTS_ROOT.exists():
        return {"reports": []}
    reports = []
    for p in sorted(REPORTS_ROOT.iterdir(), key=lambda x: x.name, reverse=True):
        if p.is_dir() and (p / "report.json").exists():
            try:
                data = json.loads((p / "report.json").read_text())
                reports.append({
                    "name": p.name,
                    "target": data.get("target"),
                    "generated_at": data.get("generated_at"),
                    "summary": data.get("summary"),
                })
            except Exception:
                continue
    return {"reports": reports}


@app.get("/reports/{name}/{filename}")
async def get_report_file(name: str, filename: str):
    if "/" in name or ".." in name or "/" in filename or ".." in filename:
        raise HTTPException(400, "bad path")
    path = REPORTS_ROOT / name / filename
    if not path.exists():
        raise HTTPException(404, "not found")
    return FileResponse(path)
