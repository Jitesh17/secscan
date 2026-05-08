"""Configuration: risk levels, scanner registry, default scan profiles."""
from enum import Enum
from dataclasses import dataclass


class Risk(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class ScannerInfo:
    name: str
    description: str
    risk: Risk
    requires_tool: str | None
    damage_estimate: str


SCANNERS: dict[str, ScannerInfo] = {
    "headers": ScannerInfo(
        name="Security headers",
        description="Checks HTTP response headers (HSTS, CSP, X-Frame-Options, etc.) "
                    "via securityheaders.com-style logic and Mozilla Observatory criteria.",
        risk=Risk.SAFE,
        requires_tool=None,
        damage_estimate="None. One GET request to the target.",
    ),
    "tls": ScannerInfo(
        name="TLS / SSL config",
        description="Tests TLS versions, ciphers, certificate, HSTS, and known vulns "
                    "(Heartbleed, ROBOT, etc.) using sslyze.",
        risk=Risk.SAFE,
        requires_tool=None,
        damage_estimate="None. Read-only TLS handshakes.",
    ),
    "subdomain": ScannerInfo(
        name="Subdomain enumeration",
        description="Passive subdomain discovery via subfinder, then liveness check via httpx.",
        risk=Risk.SAFE,
        requires_tool="subfinder",
        damage_estimate="None. Queries third-party DNS sources, not the target.",
    ),
    "nmap": ScannerInfo(
        name="Port and service scan",
        description="nmap -sV -sC at gentle timing (-T3). Identifies open ports and services.",
        risk=Risk.SAFE,
        requires_tool="nmap",
        damage_estimate="Negligible. ~1000 SYN packets over ~1 minute.",
    ),
    "nmap-aggressive": ScannerInfo(
        name="Aggressive port scan",
        description="nmap -A -T4 with vulnerability scripts. Faster, noisier, more thorough.",
        risk=Risk.MEDIUM,
        requires_tool="nmap",
        damage_estimate="Can trigger IDS/WAF alerts. May briefly load the host. "
                        "Some vuln scripts send exploit-like payloads.",
    ),
    "nuclei": ScannerInfo(
        name="Vulnerability templates",
        description="Runs ProjectDiscovery's nuclei templates (CVEs, misconfigs, exposures).",
        risk=Risk.LOW,
        requires_tool="nuclei",
        damage_estimate="Low. Sends crafted requests but does not exploit. Some templates "
                        "send payloads that may appear in logs.",
    ),
    "zap-baseline": ScannerInfo(
        name="ZAP baseline (passive)",
        description="OWASP ZAP spider + passive scan. Crawls the site and observes traffic only.",
        risk=Risk.LOW,
        requires_tool="docker",
        damage_estimate="Low. No active attacks. Spider can find pages you did not "
                        "intend to be public.",
    ),
    "zap-full": ScannerInfo(
        name="ZAP full active scan",
        description="OWASP ZAP active scan. Sends real attack payloads against forms, "
                    "parameters, and APIs.",
        risk=Risk.MEDIUM,
        requires_tool="docker",
        damage_estimate="Real attack traffic. Can: submit junk into forms, trigger emails, "
                        "fill DB with test data, get IP banned by WAF, slow the site briefly.",
    ),
    "ffuf": ScannerInfo(
        name="Content discovery",
        description="Directory and file fuzzing with ffuf using a common wordlist.",
        risk=Risk.MEDIUM,
        requires_tool="ffuf",
        damage_estimate="Generates 5k-50k requests. Will trip rate limits and WAFs. "
                        "Can fill access logs.",
    ),
    "code-trivy": ScannerInfo(
        name="Dependency scan",
        description="trivy fs scan of a local repo for vulnerable dependencies, "
                    "secrets, and misconfigurations.",
        risk=Risk.SAFE,
        requires_tool="trivy",
        damage_estimate="None. Local file scan only.",
    ),
    "code-semgrep": ScannerInfo(
        name="Code SAST",
        description="semgrep static analysis for security bugs in source code.",
        risk=Risk.SAFE,
        requires_tool="semgrep",
        damage_estimate="None. Local file scan only.",
    ),
    "code-gitleaks": ScannerInfo(
        name="Secret scan",
        description="gitleaks scans git history for leaked secrets and API keys.",
        risk=Risk.SAFE,
        requires_tool="gitleaks",
        damage_estimate="None. Local repo scan only.",
    ),
}


PROFILES = {
    "safe": ["headers", "tls", "subdomain", "nmap"],
    "default": ["headers", "tls", "subdomain", "nmap", "nuclei", "zap-baseline"],
    "code": ["code-trivy", "code-semgrep", "code-gitleaks"],
    "full": list(SCANNERS.keys()),
}


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def severity_rank(sev: str) -> int:
    sev = (sev or "unknown").lower()
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)
