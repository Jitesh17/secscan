"""Curated static remediation database.

Keyed by (scanner_name, match_pattern). The first matching entry wins.
Patterns are case-insensitive substring matches against finding titles.
"""
from dataclasses import dataclass


@dataclass
class StaticFix:
    fix: str
    rationale: str = ""
    example: str = ""


STATIC_FIXES: list[tuple[str, str, StaticFix]] = [
    ("headers", "missing hsts", StaticFix(
        fix="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to your "
            "response headers. Set it via your web server config, CDN (Cloudflare > Rules > "
            "Transform Rules > Modify Response Header), or platform-specific config "
            "(Astro/Next.js `_headers` file, Vercel `vercel.json`, Netlify `_headers`).",
        rationale="HSTS forces browsers to use HTTPS for the next year, preventing "
                  "downgrade and SSL-stripping attacks.",
        example="For Cloudflare Pages, create `public/_headers`:\n"
                "/*\n  Strict-Transport-Security: max-age=31536000; includeSubDomains",
    )),
    ("headers", "content-security-policy", StaticFix(
        fix="Add a CSP header. Start with Content-Security-Policy-Report-Only to test "
            "without breaking the site. Once no violations appear in DevTools console, "
            "switch to enforcing mode.",
        rationale="CSP is the strongest defense against XSS. It restricts which scripts "
                  "and resources the browser will execute or load.",
        example="Content-Security-Policy: default-src 'self'; script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; "
                "frame-ancestors 'none'; base-uri 'self'",
    )),
    ("headers", "x-frame-options", StaticFix(
        fix="Add `X-Frame-Options: DENY` if your site should never be framed, or "
            "`SAMEORIGIN` if you frame yourself. Modern alternative: use "
            "`frame-ancestors 'none'` directive in your CSP instead.",
        rationale="Prevents clickjacking by stopping other sites from loading yours in "
                  "an iframe.",
    )),
    ("headers", "x-content-type-options", StaticFix(
        fix="Add `X-Content-Type-Options: nosniff` to all responses.",
        rationale="Stops browsers from MIME-sniffing responses, blocking attacks where "
                  "an uploaded file is interpreted as a different content type than declared.",
    )),
    ("headers", "referrer-policy", StaticFix(
        fix="Add `Referrer-Policy: strict-origin-when-cross-origin`.",
        rationale="Prevents leaking full URL paths (which may include tokens or user IDs) "
                  "when users click links to other sites.",
    )),
    ("headers", "permissions-policy", StaticFix(
        fix="Add `Permissions-Policy: camera=(), microphone=(), geolocation=(), "
            "interest-cohort=()`.",
        rationale="Disables browser features your site does not use, reducing attack "
                  "surface and opting out of FLoC tracking.",
    )),
    ("headers", "redirect to https", StaticFix(
        fix="Configure a 301 redirect from HTTP to HTTPS at your CDN or web server. "
            "On Cloudflare: SSL/TLS > Edge Certificates > Always Use HTTPS.",
        rationale="HTTP traffic can be intercepted and modified. Forcing HTTPS is "
                  "the baseline for any modern site.",
    )),
    ("tls", "deprecated protocol", StaticFix(
        fix="Disable the deprecated TLS/SSL version on your server or CDN. Allow only "
            "TLS 1.2 and TLS 1.3. On Cloudflare: SSL/TLS > Edge Certificates > Minimum "
            "TLS Version > 1.2.",
        rationale="SSL 2.0/3.0 and TLS 1.0/1.1 have known cryptographic weaknesses and "
                  "are deprecated by all major browsers.",
    )),
    ("tls", "heartbleed", StaticFix(
        fix="Upgrade OpenSSL to 1.0.1g or later immediately. Then revoke and reissue all "
            "TLS certificates, and rotate all secrets that may have been in server memory.",
        rationale="Heartbleed allows reading server memory, which can include private "
                  "keys, session tokens, and passwords.",
    )),
    ("tls", "certificate expires", StaticFix(
        fix="Renew the certificate before expiry. If using Let's Encrypt with certbot, "
            "ensure the renewal cron job is working: `sudo certbot renew --dry-run`. "
            "If using Cloudflare, certificates auto-renew if your DNS is on Cloudflare.",
        rationale="Expired certificates cause browsers to block users with security warnings.",
    )),
    ("nmap", "ftp", StaticFix(
        fix="Disable FTP. Use SFTP (SSH) or HTTPS-based file transfer instead. If you "
            "must keep FTP, use FTPS and restrict source IPs in the firewall.",
        rationale="FTP transmits credentials and data in plaintext. There is no good "
                  "reason to expose it publicly in 2026.",
    )),
    ("nmap", "telnet", StaticFix(
        fix="Disable Telnet entirely. Use SSH instead.",
        rationale="Telnet is plaintext. Anyone on the network path can capture passwords.",
    )),
    ("nmap", "smb", StaticFix(
        fix="Block SMB (port 445/139) at the firewall from the public internet. SMB should "
            "only be accessible from trusted internal networks or over a VPN.",
        rationale="Public SMB exposure has been the vector for major worms (WannaCry, "
                  "NotPetya) and continues to expose hosts to ransomware.",
    )),
    ("nmap", "redis", StaticFix(
        fix="Bind Redis to 127.0.0.1 in `redis.conf` (`bind 127.0.0.1`), enable `requirepass`, "
            "and block port 6379 at the firewall. If clients need remote access, put it "
            "behind a VPN or use TLS with auth.",
        rationale="Open Redis is a common cause of full database compromise and "
                  "cryptocurrency mining attacks via the CONFIG SET trick.",
    )),
    ("nmap", "mongodb", StaticFix(
        fix="Enable authentication (`security.authorization: enabled` in mongod.conf), "
            "bind to localhost or a private interface, and never expose port 27017 publicly.",
        rationale="Unauthenticated MongoDB instances have leaked billions of records.",
    )),
    ("nmap", "mysql", StaticFix(
        fix="Bind MySQL to 127.0.0.1 or a private network interface. Block port 3306 at "
            "the firewall. If remote access is needed, use SSH tunneling or a VPN.",
        rationale="Direct database exposure invites brute force, exploit attempts, and "
                  "data exfiltration.",
    )),
    ("nmap", "rdp", StaticFix(
        fix="Restrict RDP (3389) to specific source IPs at the firewall, or place it behind "
            "a VPN. Enable Network Level Authentication and a strong password policy.",
        rationale="RDP brute forcing is a leading initial access vector for ransomware.",
    )),
    ("subdomain", "non-production subdomain", StaticFix(
        fix="Either: (1) take down the subdomain if unused, (2) restrict access via "
            "Cloudflare Access, IP allowlist, or HTTP basic auth, or (3) put it behind "
            "a VPN. Audit DNS records monthly to catch forgotten staging/dev hosts.",
        rationale="Non-production environments often run older code with known vulns, "
                  "have weaker auth, or expose admin panels meant for internal use.",
    )),
    ("nuclei", "default credentials", StaticFix(
        fix="Change default credentials immediately. Disable the default account if "
            "possible. Audit all internet-facing services for default-cred lockouts.",
        rationale="Default credentials are the lowest-effort way to fully compromise a system.",
    )),
    ("nuclei", "exposed", StaticFix(
        fix="Restrict access to the exposed resource. Either remove it, put it behind "
            "authentication, or block at the WAF/firewall. Investigate whether it has "
            "already been accessed by reviewing access logs.",
        rationale="Exposed admin panels, API endpoints, or backup files are direct attack "
                  "vectors and often contain sensitive data.",
    )),
    ("code-trivy", "", StaticFix(
        fix="Update the dependency to the FixedVersion shown. Run your test suite to catch "
            "breaking changes. For npm: `npm install <pkg>@<version>`. For Python: update "
            "`requirements.txt` or `pyproject.toml`. For Go: `go get <pkg>@<version>`.",
        rationale="Known CVEs in dependencies are the easiest path for attackers since "
                  "exploit code is often public.",
    )),
    ("code-gitleaks", "", StaticFix(
        fix="1) Rotate the secret immediately at the provider (AWS, GitHub, Stripe, etc). "
            "2) Remove from current code and use environment variables or a secrets manager. "
            "3) Purge from git history with `git filter-repo` or BFG Repo-Cleaner. "
            "4) Force-push and notify all collaborators to re-clone.",
        rationale="Once committed, secrets are public forever in the git history. Rotation "
                  "is mandatory; removal alone is not enough.",
    )),
    ("zap-baseline", "anti-clickjacking", StaticFix(
        fix="Same fix as missing X-Frame-Options. Add `X-Frame-Options: DENY` or use "
            "`frame-ancestors 'none'` in your CSP.",
        rationale="ZAP flags this when neither X-Frame-Options nor a CSP frame-ancestors "
                  "directive is present.",
    )),
    ("zap-baseline", "cross-domain misconfiguration", StaticFix(
        fix="Review your `Access-Control-Allow-Origin` header. Avoid `*` on endpoints that "
            "return user data or accept credentials. Use a strict allowlist of origins.",
        rationale="A wildcard CORS policy on authenticated endpoints can let any origin "
                  "read user data via a malicious site the user visits.",
    )),
    ("zap-baseline", "suspicious comments", StaticFix(
        fix="Review HTML source for comments containing TODO, FIXME, BUG, admin, password, "
            "or internal URLs. Strip HTML comments at build time. For Astro, use a Vite "
            "plugin like `vite-plugin-html` to remove comments in production builds.",
        rationale="Developer comments often leak internal logic, paths, or credentials "
                  "that aid attackers.",
    )),
]


def lookup_static_fix(scanner: str, finding_title: str) -> StaticFix | None:
    """Return the first matching static fix for a finding, or None."""
    title_lower = (finding_title or "").lower()
    for s, pattern, fix in STATIC_FIXES:
        if s != scanner:
            continue
        if not pattern or pattern.lower() in title_lower:
            return fix
    return None
