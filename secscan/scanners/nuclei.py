"""Nuclei vulnerability scanner wrapper."""
import json
import tempfile
import os
from .base import BaseScanner, Finding, ScanResult


class NucleiScanner(BaseScanner):
    name = "nuclei"
    requires_tool = "nuclei"

    def _run(self, result: ScanResult) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            output_file = f.name

        severity = self.options.get("severity", "low,medium,high,critical")
        rate_limit = str(self.options.get("rate_limit", 20))

        cmd = [
            "nuclei",
            "-u", self.target,
            "-severity", severity,
            "-rate-limit", rate_limit,
            "-jsonl",
            "-o", output_file,
            "-silent",
            "-disable-update-check",
        ]

        timeout = self.options.get("timeout", 1800)
        proc = self.shell(cmd, timeout=timeout)
        result.raw_output = (proc.stdout + "\n" + proc.stderr)[:10000]

        if not os.path.exists(output_file):
            return

        try:
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    info = item.get("info", {})
                    result.findings.append(Finding(
                        title=info.get("name", item.get("template-id", "nuclei finding")),
                        severity=info.get("severity", "info").lower(),
                        description=info.get("description", "") or "Nuclei template match.",
                        scanner=self.name,
                        target=item.get("matched-at", self.target),
                        evidence=item.get("matcher-name", "")
                                 + " " + str(item.get("extracted-results", "")),
                        remediation=info.get("remediation", ""),
                        references=info.get("reference", []) or [],
                        raw={"template_id": item.get("template-id"),
                             "tags": info.get("tags", [])},
                    ))
        finally:
            try:
                os.unlink(output_file)
            except OSError:
                pass
