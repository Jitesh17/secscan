"""Subdomain enumeration via subfinder."""
import tempfile
import os
from urllib.parse import urlparse
from .base import BaseScanner, Finding, ScanResult


class SubdomainScanner(BaseScanner):
    name = "subdomain"
    requires_tool = "subfinder"

    def _run(self, result: ScanResult) -> None:
        parsed = urlparse(self.target if "://" in self.target else f"https://{self.target}")
        domain = parsed.hostname or self.target
        if domain.startswith("www."):
            domain = domain[4:]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            output_file = f.name

        cmd = ["subfinder", "-d", domain, "-silent", "-o", output_file]
        timeout = self.options.get("timeout", 300)
        proc = self.shell(cmd, timeout=timeout)
        result.raw_output = (proc.stdout + "\n" + proc.stderr)[:5000]

        subdomains: list[str] = []
        if os.path.exists(output_file):
            with open(output_file) as f:
                subdomains = [s.strip() for s in f if s.strip()]
            os.unlink(output_file)

        if not subdomains:
            return

        result.raw["subdomains"] = subdomains  # type: ignore[attr-defined]

        result.findings.append(Finding(
            title=f"Discovered {len(subdomains)} subdomains for {domain}",
            severity="info",
            description=f"Subdomain enumeration found {len(subdomains)} hostnames.",
            scanner=self.name,
            target=domain,
            evidence="\n".join(subdomains[:50]),
            remediation="Review the list. Take down any forgotten or staging hosts that "
                        "should not be public.",
        ))

        suspect_keywords = ["dev", "staging", "test", "qa", "uat", "internal",
                            "admin", "old", "backup", "beta", "preview"]
        for sub in subdomains:
            for kw in suspect_keywords:
                if kw in sub.lower():
                    result.findings.append(Finding(
                        title=f"Potentially non-production subdomain exposed: {sub}",
                        severity="low",
                        description=f"Hostname '{sub}' contains '{kw}', suggesting a "
                                    "non-production environment that may be public.",
                        scanner=self.name,
                        target=sub,
                        remediation="Restrict access via WAF, IP allowlist, or basic auth, "
                                    "or take down if unused.",
                    ))
                    break
