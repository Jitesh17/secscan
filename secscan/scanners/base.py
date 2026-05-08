"""Base scanner class. All scanners inherit from this and return Finding lists."""
from dataclasses import dataclass, field, asdict
from datetime import datetime
import shutil
import subprocess
from typing import Any


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    scanner: str
    target: str
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    scanner: str
    target: str
    started_at: str
    finished_at: str
    status: str
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    raw_output: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "raw_output": self.raw_output[:5000],
        }


class BaseScanner:
    name: str = "base"
    requires_tool: str | None = None

    def __init__(self, target: str, options: dict[str, Any] | None = None):
        self.target = target
        self.options = options or {}

    def is_available(self) -> tuple[bool, str]:
        if self.requires_tool and shutil.which(self.requires_tool) is None:
            return False, f"required tool '{self.requires_tool}' not found in PATH"
        return True, ""

    def run(self) -> ScanResult:
        started = datetime.utcnow().isoformat()
        result = ScanResult(
            scanner=self.name,
            target=self.target,
            started_at=started,
            finished_at="",
            status="running",
        )
        ok, why = self.is_available()
        if not ok:
            result.status = "skipped"
            result.error = why
            result.finished_at = datetime.utcnow().isoformat()
            return result
        try:
            self._run(result)
            result.status = "completed"
        except subprocess.TimeoutExpired as e:
            result.status = "timeout"
            result.error = f"scan timed out: {e}"
        except Exception as e:
            result.status = "error"
            result.error = f"{type(e).__name__}: {e}"
        result.finished_at = datetime.utcnow().isoformat()
        return result

    def _run(self, result: ScanResult) -> None:
        raise NotImplementedError

    @staticmethod
    def shell(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
