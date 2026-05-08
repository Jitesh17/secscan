"""Scanner registry."""
from .base import BaseScanner, Finding, ScanResult
from .headers import HeadersScanner
from .tls import TLSScanner
from .nuclei import NucleiScanner
from .zap import ZAPBaselineScanner, ZAPFullScanner
from .nmap import NmapScanner, NmapAggressiveScanner
from .subdomain import SubdomainScanner
from .code import TrivyScanner, SemgrepScanner, GitleaksScanner


SCANNER_CLASSES: dict[str, type[BaseScanner]] = {
    "headers": HeadersScanner,
    "tls": TLSScanner,
    "nuclei": NucleiScanner,
    "zap-baseline": ZAPBaselineScanner,
    "zap-full": ZAPFullScanner,
    "nmap": NmapScanner,
    "nmap-aggressive": NmapAggressiveScanner,
    "subdomain": SubdomainScanner,
    "code-trivy": TrivyScanner,
    "code-semgrep": SemgrepScanner,
    "code-gitleaks": GitleaksScanner,
}


__all__ = ["SCANNER_CLASSES", "BaseScanner", "Finding", "ScanResult"]
