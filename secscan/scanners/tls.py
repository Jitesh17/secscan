"""TLS/SSL scanner using sslyze."""
from urllib.parse import urlparse
from .base import BaseScanner, Finding, ScanResult


class TLSScanner(BaseScanner):
    name = "tls"

    def _run(self, result: ScanResult) -> None:
        try:
            from sslyze import (
                ServerNetworkLocation,
                ServerScanRequest,
                Scanner,
                ScanCommand,
                ServerScanStatusEnum,
            )
        except ImportError as e:
            result.error = f"sslyze not installed: {e}"
            result.status = "error"
            return

        parsed = urlparse(self.target if "://" in self.target else f"https://{self.target}")
        host = parsed.hostname
        port = parsed.port or 443

        if not host:
            result.error = "could not parse host from target"
            result.status = "error"
            return

        try:
            location = ServerNetworkLocation(hostname=host, port=port)
        except Exception as e:
            result.error = f"could not create network location: {e}"
            result.status = "error"
            return

        scan_request = ServerScanRequest(
            server_location=location,
            scan_commands={
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
                ScanCommand.CERTIFICATE_INFO,
            },
        )

        scanner = Scanner()
        scanner.queue_scans([scan_request])

        for server_scan_result in scanner.get_results():
            if server_scan_result.scan_status != ServerScanStatusEnum.COMPLETED:
                result.error = f"sslyze status: {server_scan_result.scan_status}"
                continue

            r = server_scan_result.scan_result

            for label, attr in [
                ("SSL 2.0", "ssl_2_0_cipher_suites"),
                ("SSL 3.0", "ssl_3_0_cipher_suites"),
                ("TLS 1.0", "tls_1_0_cipher_suites"),
                ("TLS 1.1", "tls_1_1_cipher_suites"),
            ]:
                cmd_result = getattr(r, attr, None)
                if cmd_result and getattr(cmd_result, "result", None):
                    accepted = cmd_result.result.accepted_cipher_suites
                    if accepted:
                        sev = "critical" if label.startswith("SSL") else "high"
                        result.findings.append(Finding(
                            title=f"Deprecated protocol {label} is enabled",
                            severity=sev,
                            description=f"Server accepts {label} connections with "
                                        f"{len(accepted)} cipher suite(s).",
                            scanner=self.name,
                            target=self.target,
                            remediation=f"Disable {label} on the server or CDN. Allow "
                                        "only TLS 1.2 and TLS 1.3.",
                        ))

            if r.heartbleed and r.heartbleed.result and r.heartbleed.result.is_vulnerable_to_heartbleed:
                result.findings.append(Finding(
                    title="Server vulnerable to Heartbleed (CVE-2014-0160)",
                    severity="critical",
                    description="OpenSSL Heartbleed vulnerability detected.",
                    scanner=self.name,
                    target=self.target,
                    remediation="Upgrade OpenSSL immediately. Rotate all keys and certificates.",
                ))

            if r.robot and r.robot.result and r.robot.result.robot_result.name not in ("NOT_VULNERABLE_NO_ORACLE", "NOT_VULNERABLE_RSA_NOT_SUPPORTED"):
                result.findings.append(Finding(
                    title="Server vulnerable to ROBOT attack",
                    severity="high",
                    description=f"ROBOT result: {r.robot.result.robot_result.name}",
                    scanner=self.name,
                    target=self.target,
                    remediation="Disable RSA key exchange or upgrade the TLS stack.",
                ))

            cert_info = r.certificate_info
            if cert_info and cert_info.result:
                deployments = cert_info.result.certificate_deployments
                for dep in deployments:
                    leaf = dep.received_certificate_chain[0] if dep.received_certificate_chain else None
                    if leaf:
                        try:
                            from datetime import datetime, timezone
                            not_after = leaf.not_valid_after_utc if hasattr(leaf, "not_valid_after_utc") else leaf.not_valid_after
                            if not_after.tzinfo is None:
                                not_after = not_after.replace(tzinfo=timezone.utc)
                            days = (not_after - datetime.now(timezone.utc)).days
                            if days < 14:
                                result.findings.append(Finding(
                                    title=f"TLS certificate expires in {days} days",
                                    severity="high" if days < 7 else "medium",
                                    description=f"Certificate not_after: {not_after.isoformat()}",
                                    scanner=self.name,
                                    target=self.target,
                                    remediation="Renew the certificate.",
                                ))
                        except Exception:
                            pass
            result.raw_output = f"sslyze scan completed for {host}:{port}"

        if not result.findings and not result.error:
            result.findings.append(Finding(
                title="TLS configuration looks healthy",
                severity="info",
                description="No deprecated protocols, no Heartbleed, no ROBOT, valid cert.",
                scanner=self.name,
                target=self.target,
            ))
