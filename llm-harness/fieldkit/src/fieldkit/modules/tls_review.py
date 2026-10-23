"""Inspect certificate identity and negotiate individual TLS protocol versions."""

import asyncio
import ipaddress
import ssl
import warnings
from datetime import UTC, datetime
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from fieldkit.core.assessment import COMMON_OPTIONS, NetworkModule, write_private
from fieldkit.core.module import Option

VERSIONS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def hostname_matches(host, dns_names, ip_names):
    try:
        return str(ipaddress.ip_address(host)) in ip_names
    except ValueError:
        host = host.encode("idna").decode().lower().rstrip(".")
        for name in dns_names:
            name = name.lower().rstrip(".")
            if name == host:
                return True
            if (
                name.startswith("*.")
                and host.count(".") == name.count(".")
                and host.endswith(name[1:])
            ):
                return True
        return False


def certificate_details(der: bytes, hostname: str) -> dict:
    certificate = x509.load_der_x509_certificate(der)
    dns, ips = [], []
    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = names.get_values_for_type(x509.DNSName)
        ips = [str(ip) for ip in names.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    now = datetime.now(UTC)
    start, end = certificate.not_valid_before_utc, certificate.not_valid_after_utc
    return {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial_number": str(certificate.serial_number),
        "dns_names": dns,
        "ip_addresses": ips,
        "common_names": [
            v.value for v in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ],
        "hostname_covered": hostname_matches(hostname, dns, ips),
        "not_before": start.isoformat(),
        "not_after": end.isoformat(),
        "expired": now > end,
        "not_yet_valid": now < start,
        "days_remaining": (end - now).days,
        "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "public_key_type": type(certificate.public_key()).__name__,
    }


async def handshake(host, port, context, timeout):
    writer = None
    try:
        async with asyncio.timeout(timeout):
            _, writer = await asyncio.open_connection(
                host,
                port,
                ssl=context,
                server_hostname=host,
                ssl_handshake_timeout=timeout,
            )
            session = writer.get_extra_info("ssl_object")
            return {
                "protocol": session.version(),
                "cipher": session.cipher(),
                "der": session.getpeercert(binary_form=True),
            }
    finally:
        if writer:
            writer.close()
            try:
                async with asyncio.timeout(1):
                    await writer.wait_closed()
            except (OSError, TimeoutError):
                pass


class TLSReview(NetworkModule):
    name = "web/tls-review"
    description = "Inspect certificate identity, validity, trust, and TLS protocol support."
    options = COMMON_OPTIONS + (
        Option(
            "PROTOCOLS", list, list(VERSIONS), "TLS protocol to probe; repeat flag", "--protocol"
        ),
        Option(
            "EXPIRY_DAYS",
            int,
            30,
            "Flag certificates expiring within this many days",
            "--expiry-days",
        ),
    )

    def validate(self, settings):
        if settings["EXPIRY_DAYS"] < 0 or any(v not in VERSIONS for v in settings["PROTOCOLS"]):
            raise ValueError(
                "Use nonnegative expiry-days and protocols TLSv1, TLSv1.1, TLSv1.2, TLSv1.3"
            )

    async def assess(self, ctx):
        for base in ctx.targets:
            parsed = urlsplit(base)
            if parsed.scheme != "https":
                ctx.report["results"].append({"url": base, "outcome": "skipped_non_https"})
                continue
            host, port = parsed.hostname, parsed.port or 443
            record = {"url": base, "protocols": [], "verification": "skipped"}
            ctx.report["results"].append(record)
            der = None
            for name in ctx.settings["PROTOCOLS"]:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    context.minimum_version = context.maximum_version = VERSIONS[name]
                context.set_ciphers("ALL:@SECLEVEL=0")
                await ctx.controls.pace(base)
                try:
                    observed = await handshake(host, port, context, ctx.settings["TIMEOUT"])
                    der = observed.pop("der") or der
                    record["protocols"].append(
                        {"requested": name, "outcome": "negotiated", **observed}
                    )
                    if name in {"TLSv1", "TLSv1.1"}:
                        ctx.finding(
                            "legacy_tls",
                            f"Server negotiated {name}",
                            base,
                            severity="medium",
                            confidence="observed",
                        )
                except (ssl.SSLError, OSError, TimeoutError) as exc:
                    record["protocols"].append(
                        {
                            "requested": name,
                            "outcome": "not_negotiated",
                            "detail": str(exc) or "Timed out",
                            "note": (
                                "Failure may reflect local TLS capabilities "
                                "or network/server policy."
                            ),
                        }
                    )
            if not ctx.settings["INSECURE"]:
                await ctx.controls.pace(base)
                try:
                    verified = await handshake(
                        host, port, ssl.create_default_context(), ctx.settings["TIMEOUT"]
                    )
                    der = verified["der"] or der
                    record["verification"] = "verified"
                except ssl.SSLCertVerificationError as exc:
                    record["verification"] = "failed"
                    record["verification_detail"] = exc.verify_message
                    ctx.finding(
                        "certificate_trust",
                        "Certificate verification failed",
                        base,
                        severity="low",
                        confidence="observed",
                        detail=exc.verify_message,
                    )
                except (ssl.SSLError, OSError, TimeoutError) as exc:
                    record["verification"] = "unavailable"
                    record["verification_detail"] = str(exc) or "Timed out"
            if der:
                details = certificate_details(der, host)
                record["certificate"] = details
                path = f"certificates/{details['sha256']}.pem"
                write_private(
                    ctx.store.root / path,
                    x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM),
                )
                record["certificate_file"] = path
                for kind, condition, title in (
                    ("certificate_expired", details["expired"], "Certificate has expired"),
                    (
                        "certificate_future",
                        details["not_yet_valid"],
                        "Certificate is not yet valid",
                    ),
                    (
                        "certificate_hostname",
                        not details["hostname_covered"],
                        "Certificate SAN does not cover target hostname",
                    ),
                    (
                        "certificate_expiry",
                        0 <= details["days_remaining"] <= ctx.settings["EXPIRY_DAYS"],
                        "Certificate expires soon",
                    ),
                ):
                    if condition:
                        ctx.finding(
                            kind,
                            title,
                            base,
                            severity="low",
                            confidence="observed",
                            certificate_file=path,
                        )
            else:
                ctx.report["errors"].append(
                    {"url": base, "error": "tls_unavailable", "detail": "No certificate obtained"}
                )
