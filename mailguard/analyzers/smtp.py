from __future__ import annotations

import asyncio
import re
import socket
import ssl
from datetime import UTC, datetime

from cryptography import x509

from mailguard.config import AppConfig
from mailguard.core.utils import is_public_ip
from mailguard.models import MTASTSAnalysis, MXHost, SMTPAnalysis, Status, TLSProbe

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_RE = re.compile(r"(RC4|3DES|DES|NULL|MD5|EXP|aNULL)", re.IGNORECASE)


async def analyze_smtp(
    mx_hosts: list[MXHost],
    mta_sts: MTASTSAnalysis,
    config: AppConfig,
) -> SMTPAnalysis:
    if not mx_hosts:
        return SMTPAnalysis(status=Status.SKIPPED, issues=["SMTP checks skipped because no MX records were found."])
    selected_hosts = mx_hosts[: config.smtp_max_hosts]
    require_mta_sts = bool(mta_sts.policy and mta_sts.policy.mode == "enforce")
    probes = await asyncio.gather(
        *[
            asyncio.to_thread(
                _probe_smtp_host,
                host.hostname,
                host.addresses,
                require_mta_sts,
                config.smtp_timeout,
                config.allow_private_mx_probe,
            )
            for host in selected_hosts
        ]
    )
    analysis = SMTPAnalysis(hosts=probes)
    if any(item.open_relay_suspected or (item.starttls_advertised and not item.starttls_successful) for item in probes):
        analysis.status = Status.FAIL
    elif any(item.weak_cipher or item.weak_protocol or item.downgrade_possible for item in probes):
        analysis.status = Status.WARN
    else:
        analysis.status = Status.PASS
    analysis.issues = [issue for probe in probes for issue in probe.issues]
    return analysis


def _probe_smtp_host(
    host: str,
    addresses: list[str],
    require_mta_sts: bool,
    timeout: float,
    allow_private_probe: bool,
) -> TLSProbe:
    probe = TLSProbe(host=host)
    if addresses and not allow_private_probe and not any(is_public_ip(address) for address in addresses):
        probe.status = Status.SKIPPED
        probe.issues.append("Skipping SMTP probe for non-public MX host.")
        return probe
    sock: socket.socket | ssl.SSLSocket | None = None
    try:
        sock = socket.create_connection((host, 25), timeout=timeout)
        sock.settimeout(timeout)
        probe.banner = _read_response(sock)
        capabilities = _send_command(sock, "EHLO mailguard.local")
        upper_capabilities = capabilities.upper()
        probe.starttls_advertised = "STARTTLS" in upper_capabilities
        probe.vrfy_enabled = _command_supported(_send_command(sock, "VRFY postmaster"))
        probe.expn_enabled = _command_supported(_send_command(sock, "EXPN postmaster"))
        if probe.starttls_advertised:
            response = _send_command(sock, "STARTTLS")
            if response.startswith("220"):
                secure_socket, tls_probe = _upgrade_to_tls(sock, host, timeout)
                sock = secure_socket
                probe.starttls_successful = True
                probe.tls_version = tls_probe["tls_version"]
                probe.cipher = tls_probe["cipher"]
                probe.certificate_subject = tls_probe["certificate_subject"]
                probe.certificate_issuer = tls_probe["certificate_issuer"]
                probe.certificate_expires_at = tls_probe["certificate_expires_at"]
                probe.certificate_valid = tls_probe["certificate_valid"]
                probe.certificate_errors = tls_probe["certificate_errors"]
                probe.weak_protocol = probe.tls_version in WEAK_PROTOCOLS
                probe.weak_cipher = bool(probe.cipher and WEAK_CIPHER_RE.search(probe.cipher))
                _send_command(sock, "EHLO mailguard.local")
            else:
                probe.issues.append("STARTTLS was advertised but negotiation failed.")
        else:
            probe.issues.append("STARTTLS not advertised on port 25.")
        if not probe.starttls_advertised:
            probe.downgrade_possible = True
        elif not require_mta_sts:
            probe.downgrade_possible = True
            probe.issues.append("Domain lacks enforcing MTA-STS, so STARTTLS stripping remains possible.")
        relay_mail = _send_command(sock, "MAIL FROM:<relay-test@mailguard.invalid>")
        relay_rcpt = _send_command(sock, "RCPT TO:<relay-target@example.invalid>")
        if relay_mail.startswith("250") and relay_rcpt.startswith(("250", "251", "252")):
            probe.open_relay_suspected = True
            probe.open_relay_evidence.extend([relay_mail, relay_rcpt])
            probe.issues.append("Server accepted unauthenticated external relay test addresses.")
        _send_command(sock, "RSET")
        _send_command(sock, "QUIT")
    except (OSError, ssl.SSLError, socket.timeout) as exc:
        probe.status = Status.ERROR
        probe.issues.append(str(exc))
        return probe
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if probe.open_relay_suspected or (probe.starttls_advertised and not probe.starttls_successful):
        probe.status = Status.FAIL
    elif not probe.starttls_advertised or probe.weak_protocol or probe.weak_cipher or probe.downgrade_possible:
        probe.status = Status.WARN
    else:
        probe.status = Status.PASS
    return probe


def _upgrade_to_tls(sock: socket.socket, host: str, timeout: float) -> tuple[ssl.SSLSocket, dict[str, object]]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    secure_socket = context.wrap_socket(sock, server_hostname=host)
    secure_socket.settimeout(timeout)
    cert_errors: list[str] = []
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    certificate_expires_at = None
    certificate_valid = False
    certificate_bytes = secure_socket.getpeercert(binary_form=True)
    if certificate_bytes:
        certificate = x509.load_der_x509_certificate(certificate_bytes)
        certificate_subject = certificate.subject.rfc4514_string()
        certificate_issuer = certificate.issuer.rfc4514_string()
        certificate_expires_at = certificate.not_valid_after_utc if hasattr(certificate, "not_valid_after_utc") else certificate.not_valid_after.replace(tzinfo=UTC)
        certificate_valid = certificate_expires_at > datetime.now(UTC)
        if not certificate_valid:
            cert_errors.append("Certificate is expired.")
    else:
        cert_errors.append("Peer certificate missing.")
    cipher = secure_socket.cipher()
    return secure_socket, {
        "tls_version": secure_socket.version(),
        "cipher": cipher[0] if cipher else None,
        "certificate_subject": certificate_subject,
        "certificate_issuer": certificate_issuer,
        "certificate_expires_at": certificate_expires_at,
        "certificate_valid": certificate_valid,
        "certificate_errors": cert_errors,
    }


def _read_response(sock: socket.socket | ssl.SSLSocket) -> str:
    lines: list[str] = []
    buffer = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk
        while b"\n" in buffer:
            raw_line, buffer = buffer.split(b"\n", 1)
            line = raw_line.decode("utf-8", errors="ignore").strip()
            if not line:
                continue
            lines.append(line)
            if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
                return "\n".join(lines)
        if len(lines) > 20:
            break
    return "\n".join(lines)


def _send_command(sock: socket.socket | ssl.SSLSocket, command: str) -> str:
    sock.sendall(f"{command}\r\n".encode("ascii"))
    return _read_response(sock)


def _command_supported(response: str) -> bool:
    return bool(response and not response.startswith(("500", "502", "504")))
