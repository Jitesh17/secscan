"""OWASP ZAP scanners (baseline and full active) via Docker."""
import os
import re
import tempfile
from .base import BaseScanner, Finding, ScanResult


SEVERITY_MAP = {
    "WARN": "low",
    "FAIL": "medium",
    "INFO": "info",
}


def _parse_zap_output(text: str, target: str, scanner_name: str) -> list[Finding]:
    """Parse ZAP baseline-style stdout into Finding objects."""
    findings: list[Finding] = []
    pattern = re.compile(
        r"(WARN-NEW|FAIL-NEW|WARN-INPROG|FAIL-INPROG):\s*([^\[]+)\s*\[(\d+)\]\s*x\s*(\d+)",
        re.MULTILINE,
    )
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = pattern.search(line)
        if not m:
            continue
        kind, title, plugin_id, count = m.groups()
        sev_word = "FAIL" if kind.startswith("FAIL") else "WARN"
        urls = []
        for j in range(i + 1, min(i + 20, len(lines))):
            nxt = lines[j].strip()
            if nxt.startswith("https://") or nxt.startswith("http://"):
                urls.append(nxt)
            elif pattern.search(nxt):
                break
        findings.append(Finding(
            title=title.strip(),
            severity=SEVERITY_MAP.get(sev_word, "low"),
            description=f"OWASP ZAP plugin {plugin_id} reported {count} instance(s).",
            scanner=scanner_name,
            target=target,
            evidence="\n".join(urls[:10]),
            remediation="See OWASP ZAP plugin documentation for plugin id " + plugin_id,
            references=[
                f"https://www.zaproxy.org/docs/alerts/{plugin_id}/",
            ],
            raw={"plugin_id": plugin_id, "count": int(count)},
        ))
    return findings


class ZAPBaselineScanner(BaseScanner):
    name = "zap-baseline"
    requires_tool = "docker"

    def _run(self, result: ScanResult) -> None:
        workdir = tempfile.mkdtemp(prefix="zap-")
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{workdir}:/zap/wrk/:rw",
            "zaproxy/zap-stable",
            "zap-baseline.py",
            "-t", self.target,
            "-r", "report.html",
            "-J", "report.json",
        ]
        timeout = self.options.get("timeout", 1200)
        proc = self.shell(cmd, timeout=timeout)
        result.raw_output = (proc.stdout + "\n" + proc.stderr)[:15000]
        result.findings = _parse_zap_output(proc.stdout, self.target, self.name)


class ZAPFullScanner(BaseScanner):
    name = "zap-full"
    requires_tool = "docker"

    def _run(self, result: ScanResult) -> None:
        workdir = tempfile.mkdtemp(prefix="zap-full-")
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{workdir}:/zap/wrk/:rw",
            "zaproxy/zap-stable",
            "zap-full-scan.py",
            "-t", self.target,
            "-r", "report.html",
            "-J", "report.json",
        ]
        timeout = self.options.get("timeout", 5400)
        proc = self.shell(cmd, timeout=timeout)
        result.raw_output = (proc.stdout + "\n" + proc.stderr)[:15000]
        result.findings = _parse_zap_output(proc.stdout, self.target, self.name)
        for f in result.findings:
            if f.severity == "low":
                f.severity = "medium"
            elif f.severity == "medium":
                f.severity = "high"
