"""Code scanners: trivy (SCA), semgrep (SAST), gitleaks (secrets)."""
import json
import os
import tempfile
from .base import BaseScanner, Finding, ScanResult


def _resolve_repo(options: dict) -> str | None:
    repo = options.get("repo")
    if not repo:
        return None
    repo = os.path.expanduser(repo)
    if not os.path.isdir(repo):
        return None
    return repo


class TrivyScanner(BaseScanner):
    name = "code-trivy"
    requires_tool = "trivy"

    def _run(self, result: ScanResult) -> None:
        repo = _resolve_repo(self.options)
        if not repo:
            result.error = "no --repo path provided or path does not exist"
            result.status = "error"
            return

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name

        cmd = ["trivy", "fs", "--scanners", "vuln,secret,misconfig",
               "--format", "json", "--output", output_file,
               "--quiet", repo]
        timeout = self.options.get("timeout", 1200)
        proc = self.shell(cmd, timeout=timeout)
        result.raw_output = (proc.stdout + "\n" + proc.stderr)[:5000]

        if not os.path.exists(output_file):
            return

        try:
            with open(output_file) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            result.error = f"could not parse trivy output: {e}"
            return
        finally:
            try:
                os.unlink(output_file)
            except OSError:
                pass

        for r in data.get("Results", []):
            target = r.get("Target", repo)
            for vuln in r.get("Vulnerabilities", []) or []:
                result.findings.append(Finding(
                    title=f"{vuln.get('VulnerabilityID')}: {vuln.get('PkgName')} "
                          f"{vuln.get('InstalledVersion')}",
                    severity=str(vuln.get("Severity", "unknown")).lower(),
                    description=vuln.get("Title", "") or vuln.get("Description", "")[:500],
                    scanner=self.name,
                    target=target,
                    remediation=f"Upgrade to {vuln.get('FixedVersion')}"
                                if vuln.get("FixedVersion") else "No fixed version available.",
                    references=[vuln.get("PrimaryURL")] if vuln.get("PrimaryURL") else [],
                ))
            for secret in r.get("Secrets", []) or []:
                result.findings.append(Finding(
                    title=f"Secret detected: {secret.get('RuleID')}",
                    severity=str(secret.get("Severity", "high")).lower(),
                    description=secret.get("Title", "Hardcoded secret found in source."),
                    scanner=self.name,
                    target=f"{target}:{secret.get('StartLine')}",
                    evidence=secret.get("Match", "")[:200],
                    remediation="Rotate the credential and remove from source. "
                                "Use a secrets manager or environment variables.",
                ))
            for misc in r.get("Misconfigurations", []) or []:
                result.findings.append(Finding(
                    title=f"Misconfiguration: {misc.get('ID')} - {misc.get('Title')}",
                    severity=str(misc.get("Severity", "medium")).lower(),
                    description=misc.get("Description", ""),
                    scanner=self.name,
                    target=target,
                    remediation=misc.get("Resolution", ""),
                    references=[misc.get("PrimaryURL")] if misc.get("PrimaryURL") else [],
                ))


class SemgrepScanner(BaseScanner):
    name = "code-semgrep"
    requires_tool = "semgrep"

    def _run(self, result: ScanResult) -> None:
        repo = _resolve_repo(self.options)
        if not repo:
            result.error = "no --repo path provided or path does not exist"
            result.status = "error"
            return

        cmd = ["semgrep", "--config=auto", "--json", "--quiet",
               "--timeout", "60", repo]
        timeout = self.options.get("timeout", 1800)
        proc = self.shell(cmd, timeout=timeout)
        result.raw_output = proc.stderr[:5000]

        try:
            data = json.loads(proc.stdout) if proc.stdout else {}
        except json.JSONDecodeError as e:
            result.error = f"could not parse semgrep output: {e}"
            return

        sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

        for r in data.get("results", []):
            extra = r.get("extra", {})
            sev = sev_map.get(str(extra.get("severity", "")).upper(), "medium")
            result.findings.append(Finding(
                title=r.get("check_id", "semgrep finding"),
                severity=sev,
                description=extra.get("message", "")[:1000],
                scanner=self.name,
                target=f"{r.get('path')}:{r.get('start', {}).get('line')}",
                evidence=extra.get("lines", "")[:300],
                remediation=extra.get("metadata", {}).get("fix") or
                            "Review and refactor according to the rule guidance.",
                references=extra.get("metadata", {}).get("references", []) or [],
            ))


class GitleaksScanner(BaseScanner):
    name = "code-gitleaks"
    requires_tool = "gitleaks"

    def _run(self, result: ScanResult) -> None:
        repo = _resolve_repo(self.options)
        if not repo:
            result.error = "no --repo path provided or path does not exist"
            result.status = "error"
            return

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            output_file = f.name

        cmd = ["gitleaks", "detect", "--source", repo,
               "--report-path", output_file, "--report-format", "json",
               "--no-git", "--no-banner"]
        timeout = self.options.get("timeout", 600)
        proc = self.shell(cmd, timeout=timeout)
        result.raw_output = (proc.stdout + "\n" + proc.stderr)[:5000]

        if not os.path.exists(output_file):
            return

        try:
            with open(output_file) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            data = []
        finally:
            try:
                os.unlink(output_file)
            except OSError:
                pass

        for item in data or []:
            result.findings.append(Finding(
                title=f"Secret leaked: {item.get('RuleID', 'unknown')}",
                severity="high",
                description=item.get("Description", "Secret detected in repository."),
                scanner=self.name,
                target=f"{item.get('File')}:{item.get('StartLine')}",
                evidence=str(item.get("Match", ""))[:200],
                remediation="Rotate the secret immediately. Remove from history with "
                            "git filter-repo or BFG. Move to a secrets manager.",
            ))
