"""Security headers scanner. Checks HTTP response headers."""
import requests
from .base import BaseScanner, Finding, ScanResult


HEADER_RULES = [
    {
        "header": "Strict-Transport-Security",
        "severity": "high",
        "title": "Missing HSTS header",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
    },
    {
        "header": "Content-Security-Policy",
        "severity": "medium",
        "title": "Missing Content-Security-Policy header",
        "remediation": "Define a CSP. Start with Content-Security-Policy-Report-Only to test "
                       "without breaking the site.",
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/CSP",
    },
    {
        "header": "X-Frame-Options",
        "severity": "medium",
        "title": "Missing X-Frame-Options header",
        "remediation": "Add: X-Frame-Options: DENY (or use frame-ancestors in CSP)",
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    {
        "header": "X-Content-Type-Options",
        "severity": "low",
        "title": "Missing X-Content-Type-Options header",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    {
        "header": "Referrer-Policy",
        "severity": "low",
        "title": "Missing Referrer-Policy header",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    {
        "header": "Permissions-Policy",
        "severity": "low",
        "title": "Missing Permissions-Policy header",
        "remediation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "ref": "https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy",
    },
]


LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


class HeadersScanner(BaseScanner):
    name = "headers"

    def _run(self, result: ScanResult) -> None:
        try:
            r = requests.get(self.target, timeout=15, allow_redirects=True)
        except requests.RequestException as e:
            result.error = str(e)
            result.status = "error"
            return

        result.raw_output = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        headers_lower = {k.lower(): v for k, v in r.headers.items()}

        for rule in HEADER_RULES:
            if rule["header"].lower() not in headers_lower:
                result.findings.append(Finding(
                    title=rule["title"],
                    severity=rule["severity"],
                    description=f"The response from {self.target} does not include the "
                                f"{rule['header']} header.",
                    scanner=self.name,
                    target=self.target,
                    remediation=rule["remediation"],
                    references=[rule["ref"]],
                ))

        for h in LEAKY_HEADERS:
            if h.lower() in headers_lower:
                val = headers_lower[h.lower()]
                if val.strip().lower() in ("cloudflare", ""):
                    continue
                result.findings.append(Finding(
                    title=f"Server software disclosed via {h}",
                    severity="info",
                    description=f"{h}: {val}",
                    scanner=self.name,
                    target=self.target,
                    remediation=f"Remove or mask the {h} header at the web server or CDN.",
                ))

        if r.url.startswith("http://"):
            result.findings.append(Finding(
                title="Site does not redirect to HTTPS",
                severity="high",
                description=f"Final URL after redirects is {r.url}, still HTTP.",
                scanner=self.name,
                target=self.target,
                remediation="Configure 301 redirect from HTTP to HTTPS at the server or CDN.",
            ))
