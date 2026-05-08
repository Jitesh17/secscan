"""secscan command-line interface."""
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import ipaddress
import shutil
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .config import SCANNERS, PROFILES, Risk, severity_rank
from .runner import run_scans
from .reports import write_html, write_markdown, write_json


console = Console()


def _is_ip(target: str) -> bool:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.hostname or target
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _risk_warning(scanner_names: list[str], i_accept_risk: bool) -> bool:
    """Print risk summary and return True if scan should proceed."""
    risky = []
    for name in scanner_names:
        info = SCANNERS.get(name)
        if not info:
            continue
        if info.risk in (Risk.MEDIUM, Risk.HIGH):
            risky.append((name, info))

    if not risky:
        return True

    table = Table(title="[yellow]Risky scanners selected[/yellow]", show_lines=True)
    table.add_column("Scanner", style="cyan")
    table.add_column("Risk", style="red")
    table.add_column("What can happen", style="white")
    for name, info in risky:
        table.add_row(name, info.risk.value.upper(), info.damage_estimate)
    console.print(table)

    if i_accept_risk:
        console.print("[yellow]--i-accept-risk passed. Proceeding.[/yellow]")
        return True

    return click.confirm(
        "\nThe scanners above can cause real side effects on the target. "
        "Do you own this target and accept the risk?",
        default=False,
    )


@click.group()
@click.version_option(version=__version__, prog_name="secscan")
def main():
    """secscan - automated web security scanner."""


@main.command()
@click.argument("target")
@click.option("--scans", default="default",
              help="Comma-separated scanners or profile name (safe, default, code, full).")
@click.option("--profile", default=None, help="Use a named profile (overrides --scans).")
@click.option("--repo", default=None, help="Local repo path for code scanners.")
@click.option("--output", "-o", default="./reports",
              help="Output directory for reports.")
@click.option("--workers", default=4, help="Parallel scanners.")
@click.option("--rate-limit", default=20, help="Requests per second for nuclei.")
@click.option("--allow-ip", is_flag=True, help="Allow scanning IP addresses.")
@click.option("--i-accept-risk", is_flag=True,
              help="Skip confirmation for risky scanners.")
@click.option("--severity", default="low,medium,high,critical",
              help="Severity filter for nuclei.")
@click.option("--enrich/--no-enrich", default=True,
              help="Apply remediation enrichment (static DB always; AI when "
                   "ANTHROPIC_API_KEY is set). Default: on.")
@click.option("--ai/--no-ai", default=True,
              help="Use Claude API for context-aware fixes if API key set. "
                   "Default: on.")
@click.option("--no-code", is_flag=True,
              help="Do not send code/config snippets to the AI. "
                   "Metadata-only enrichment.")
@click.option("--max-ai-findings", default=50,
              help="Cap on findings sent to AI (cost control).")
def scan(target, scans, profile, repo, output, workers, rate_limit,
         allow_ip, i_accept_risk, severity, enrich, ai, no_code,
         max_ai_findings):
    """Run security scans against TARGET (URL or hostname)."""

    if "://" not in target:
        target = "https://" + target

    if _is_ip(target) and not allow_ip:
        console.print("[red]Target appears to be an IP address.[/red]")
        console.print("Pass --allow-ip if you actually intend to scan an IP. "
                      "Use a hostname otherwise.")
        sys.exit(2)

    if profile:
        scanner_names = PROFILES.get(profile)
        if not scanner_names:
            console.print(f"[red]Unknown profile: {profile}[/red]")
            console.print(f"Profiles: {', '.join(PROFILES.keys())}")
            sys.exit(2)
    elif scans in PROFILES:
        scanner_names = PROFILES[scans]
    else:
        scanner_names = [s.strip() for s in scans.split(",") if s.strip()]

    unknown = [s for s in scanner_names if s not in SCANNERS]
    if unknown:
        console.print(f"[red]Unknown scanners: {', '.join(unknown)}[/red]")
        console.print(f"Available: {', '.join(SCANNERS.keys())}")
        sys.exit(2)

    console.print(Panel.fit(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Scanners:[/bold] {', '.join(scanner_names)}\n"
        f"[bold]Output:[/bold] {output}",
        title="secscan",
        border_style="blue",
    ))

    if not _risk_warning(scanner_names, i_accept_risk):
        console.print("[yellow]Aborted.[/yellow]")
        sys.exit(1)

    options = {
        "repo": repo,
        "rate_limit": rate_limit,
        "severity": severity,
    }

    results = run_scans(
        target=target,
        scanner_names=scanner_names,
        options=options,
        max_workers=workers,
        console=console,
    )

    if enrich:
        from .remediation import enrich_findings, build_config_from_env
        all_findings = [f for r in results for f in r.findings]
        if all_findings:
            cfg = build_config_from_env(
                enable_ai=ai,
                include_code=not no_code,
                repo=repo,
            )
            cfg.max_findings = max_ai_findings
            mode = "static + AI" if cfg.enabled else "static only"
            if ai and not cfg.enabled:
                mode += " (set ANTHROPIC_API_KEY for AI enrichment)"
            console.print(f"\n[cyan]Enriching {len(all_findings)} findings "
                          f"({mode})...[/cyan]")

            def _progress(done, total):
                console.print(f"  enriched {done}/{total}", end="\r")

            enrich_findings(
                all_findings,
                cfg,
                cache_path=str(Path(output) / ".enrich-cache.json"),
                on_progress=_progress if cfg.enabled else None,
            )
            console.print()

    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
    run_dir = Path(output) / f"{safe_target}-{timestamp}"

    html_path = write_html(target, results, run_dir)
    md_path = write_markdown(target, results, run_dir)
    json_path = write_json(target, results, run_dir)

    console.print()
    console.print(Panel.fit(
        f"[green]Scan complete.[/green]\n\n"
        f"HTML:     [cyan]{html_path}[/cyan]\n"
        f"Markdown: [cyan]{md_path}[/cyan]\n"
        f"JSON:     [cyan]{json_path}[/cyan]",
        title="Reports",
        border_style="green",
    ))

    sev_counts: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            sev = (f.severity or "unknown").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

    if sev_counts:
        summary_table = Table(title="Findings by severity")
        summary_table.add_column("Severity")
        summary_table.add_column("Count", justify="right")
        for sev in sorted(sev_counts, key=severity_rank):
            color = {"critical": "red", "high": "orange3", "medium": "yellow",
                     "low": "blue", "info": "white"}.get(sev, "white")
            summary_table.add_row(f"[{color}]{sev}[/]", str(sev_counts[sev]))
        console.print(summary_table)

    high_or_worse = sev_counts.get("critical", 0) + sev_counts.get("high", 0)
    sys.exit(1 if high_or_worse > 0 else 0)


@main.command()
def list_scanners():
    """List available scanners and their risk levels."""
    table = Table(title="Available scanners")
    table.add_column("Name", style="cyan")
    table.add_column("Risk")
    table.add_column("Tool")
    table.add_column("Available")
    table.add_column("Description")
    missing = []
    for name, info in SCANNERS.items():
        risk_color = {"safe": "green", "low": "blue",
                      "medium": "yellow", "high": "red"}[info.risk.value]
        if info.requires_tool is None:
            available_cell = "[green]yes[/]"
        elif shutil.which(info.requires_tool):
            available_cell = "[green]yes[/]"
        else:
            available_cell = "[red]missing[/]"
            missing.append((name, info.requires_tool))
        table.add_row(
            name,
            f"[{risk_color}]{info.risk.value}[/]",
            info.requires_tool or "(builtin)",
            available_cell,
            info.description,
        )
    console.print(table)
    if missing:
        tools_needed = sorted({tool for _, tool in missing})
        console.print(
            f"\n[yellow]{len(missing)} scanner(s) cannot run "
            f"because their tool is not on PATH: "
            f"{', '.join(tools_needed)}.[/yellow]"
        )


@main.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8765)
def serve(host, port):
    """Start the web dashboard."""
    try:
        import uvicorn
        from .dashboard import app
    except ImportError as e:
        console.print(f"[red]Missing dependencies for dashboard: {e}[/red]")
        sys.exit(2)
    console.print(f"[green]Dashboard at http://{host}:{port}[/green]")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
