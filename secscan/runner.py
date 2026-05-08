"""Parallel scan runner with progress display."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from .scanners import SCANNER_CLASSES, ScanResult


def run_scans(
    target: str,
    scanner_names: list[str],
    options: dict | None = None,
    max_workers: int = 4,
    on_complete: Callable[[ScanResult], None] | None = None,
    console: Console | None = None,
) -> list[ScanResult]:
    """Run scanners in parallel and return all results."""
    options = options or {}
    console = console or Console()
    results: list[ScanResult] = []

    scanners = []
    for name in scanner_names:
        cls = SCANNER_CLASSES.get(name)
        if not cls:
            console.print(f"[yellow]Unknown scanner: {name}[/yellow]")
            continue
        scanners.append((name, cls(target, options)))

    if not scanners:
        return []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        tasks = {
            name: progress.add_task(f"[cyan]{name}[/cyan] running...", total=None)
            for name, _ in scanners
        }

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(s.run): name for name, s in scanners}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = ScanResult(
                        scanner=name,
                        target=target,
                        started_at=datetime.utcnow().isoformat(),
                        finished_at=datetime.utcnow().isoformat(),
                        status="error",
                        error=str(e),
                    )
                results.append(res)
                status_color = {
                    "completed": "green",
                    "skipped": "yellow",
                    "error": "red",
                    "timeout": "red",
                }.get(res.status, "white")
                count = len(res.findings)
                progress.update(
                    tasks[name],
                    description=f"[{status_color}]{name}[/] {res.status} "
                                f"({count} findings)",
                    completed=1,
                    total=1,
                )
                if on_complete:
                    on_complete(res)

    return results
