"""nmap scanners (gentle and aggressive)."""
import re
from urllib.parse import urlparse
from .base import BaseScanner, Finding, ScanResult


def _host_from_target(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return parsed.hostname or target


PORT_LINE = re.compile(r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.*))?")


class NmapScanner(BaseScanner):
    name = "nmap"
    requires_tool = "nmap"

    def _run(self, result: ScanResult) -> None:
        host = _host_from_target(self.target)
        cmd = ["nmap", "-sV", "-sC", "-T3", "-Pn", host]
        timeout = self.options.get("timeout", 600)
        proc = self.shell(cmd, timeout=timeout)
        result.raw_output = proc.stdout

        risky_ports = {"21": "FTP", "23": "Telnet", "139": "NetBIOS", "445": "SMB",
                       "3389": "RDP", "5900": "VNC", "6379": "Redis", "27017": "MongoDB",
                       "3306": "MySQL", "5432": "PostgreSQL", "9200": "Elasticsearch"}

        for line in proc.stdout.splitlines():
            m = PORT_LINE.match(line.strip())
            if not m:
                continue
            port, proto, state, service, version = m.groups()
            if state != "open":
                continue
            sev = "info"
            title = f"Open port {port}/{proto}: {service}"
            desc = f"Service {service} {(version or '').strip()} on port {port}/{proto}."
            if port in risky_ports:
                sev = "medium"
                title = f"Sensitive service {risky_ports[port]} exposed on port {port}"
                desc += f" {risky_ports[port]} should not normally be public."
            result.findings.append(Finding(
                title=title,
                severity=sev,
                description=desc,
                scanner=self.name,
                target=host,
                evidence=line.strip(),
                remediation="Restrict access to internal network or VPN if not intentionally public.",
            ))


class NmapAggressiveScanner(BaseScanner):
    name = "nmap-aggressive"
    requires_tool = "nmap"

    def _run(self, result: ScanResult) -> None:
        host = _host_from_target(self.target)
        cmd = ["nmap", "-A", "-T4", "-Pn", "--script", "vuln", host]
        timeout = self.options.get("timeout", 1800)
        proc = self.shell(cmd, timeout=timeout)
        result.raw_output = proc.stdout

        for line in proc.stdout.splitlines():
            m = PORT_LINE.match(line.strip())
            if m:
                port, proto, state, service, version = m.groups()
                if state == "open":
                    result.findings.append(Finding(
                        title=f"Open port {port}/{proto}: {service}",
                        severity="info",
                        description=f"{service} {(version or '').strip()}",
                        scanner=self.name,
                        target=host,
                        evidence=line.strip(),
                    ))
            if "VULNERABLE:" in line:
                result.findings.append(Finding(
                    title="nmap vuln script reported vulnerability",
                    severity="high",
                    description=line.strip(),
                    scanner=self.name,
                    target=host,
                    evidence=line.strip(),
                ))
