"""
Module · TLS / certificate review (source code "T").

For every HTTPS host and every TLS port the scan found, this negotiates a
connection and reports the transport-security posture:

  * negotiated protocol version and cipher
  * which legacy protocols still handshake (SSLv3 / TLS 1.0 / TLS 1.1)
  * the leaf certificate · subject, issuer, validity window, SAN list, serial,
    signature algorithm, key size, whether it is a wildcard or self-signed
  * whether the certificate actually covers the hostname
  * the verified chain length

It uses only the standard library `ssl` for negotiation and (when installed) the
`cryptography` package for robust certificate parsing · both are already present.
Findings are raised for expired / soon-to-expire / self-signed / mismatched
certificates and for weak protocols and ciphers. Everything is stored on the
subdomain's record so the panel can show the certificate detail.

Skipped entirely while a scan runs over Tor · the review opens raw TLS sockets,
which would sidestep the SOCKS proxy and leak the real client. The Tor guarantee
wins over the extra coverage.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone

from . import config, tor
from .schema import ScanResult
from .util import get_logger

log = get_logger("tls_analysis")

SRC = config.SOURCE_CODES["tls"]             # "T"

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    _HAVE_CRYPTO = True
except Exception:                            # pragma: no cover
    _HAVE_CRYPTO = False

_WEAK_PROTOCOLS = [("SSLv3", ssl.TLSVersion.SSLv3, "high"),
                   ("TLSv1", ssl.TLSVersion.TLSv1, "medium"),
                   ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "medium")]

_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON")


def _no_verify_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _collect_targets(result: ScanResult) -> list[tuple[str, int]]:
    targets: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()

    def add(host: str, port: int) -> None:
        host = (host or "").strip().lower().rstrip(".")
        if not host or (host, port) in seen:
            return
        seen.add((host, port))
        targets.append((host, port))

    for sub in result._subdomains.values():       # type: ignore[attr-defined]
        http = sub.get("http") or {}
        if http.get("scheme") == "https" and http.get("status") and not http.get("error"):
            add(sub["host"], 443)
    for rec in result._ips.values():               # type: ignore[attr-defined]
        for p in rec.get("ports") or []:
            svc = (p.get("service") or "").lower()
            if p.get("tunnel") == "ssl" or "https" in svc or svc == "ssl/http" \
                    or p.get("port") in (443, 8443, 4443, 9443):
                hosts = rec.get("subdomains") or [rec["ip"]]
                for h in hosts[:2]:
                    add(h, p["port"])
    return targets[: config.TLS_ANALYSIS_MAX_HOSTS]


def _parse_cert(der: bytes) -> dict:
    """Leaf-certificate fields from DER. Uses cryptography when available; returns
    a minimal dict otherwise (negotiation data is still useful without it)."""
    if not (_HAVE_CRYPTO and der):
        return {}
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return {}

    def _cn(name) -> str | None:
        try:
            attrs = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            return attrs[0].value if attrs else None
        except Exception:
            return None

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        pass

    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:                   # older cryptography
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    key = cert.public_key()
    key_bits = getattr(key, "key_size", None)
    key_type = ("RSA" if isinstance(key, rsa.RSAPublicKey)
                else "EC" if isinstance(key, ec.EllipticCurvePublicKey) else
                type(key).__name__)

    subject_cn = _cn(cert.subject)
    issuer_cn = _cn(cert.issuer)
    days_left = (not_after - datetime.now(timezone.utc)).days
    return {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "issuer": issuer_cn,
        "san": sans,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_to_expiry": days_left,
        "expired": days_left < 0,
        "self_signed": cert.subject == cert.issuer,
        "wildcard": any(n.startswith("*.") for n in sans) or bool(subject_cn and subject_cn.startswith("*.")),
        "serial": format(cert.serial_number, "x"),
        "sig_algorithm": getattr(getattr(cert, "signature_hash_algorithm", None), "name", None),
        "key_type": key_type,
        "key_bits": key_bits,
    }


def _host_matches(host: str, cert: dict) -> bool:
    host = host.lower()
    if _is_ip(host):
        return True                          # IP targets: name match is moot
    names = list(cert.get("san") or [])
    if not names and cert.get("subject_cn"):
        names = [cert["subject_cn"]]
    for n in names:
        n = (n or "").lower()
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count(".") and host.endswith(n[1:]):
            return True
    return False


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _supports_version(host: str, port: int, version: ssl.TLSVersion) -> bool:
    ctx = _no_verify_ctx()
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, OSError):
        return False
    try:
        with socket.create_connection((host, port), timeout=config.TLS_CONNECT_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=None if _is_ip(host) else host):
                return True
    except Exception:
        return False


def _analyze_one(host: str, port: int) -> dict:
    out: dict = {"host": host, "port": port}
    ctx = _no_verify_ctx()
    try:
        with socket.create_connection((host, port), timeout=config.TLS_CONNECT_TIMEOUT) as raw:
            sni = None if _is_ip(host) else host
            with ctx.wrap_socket(raw, server_hostname=sni) as ss:
                out["version"] = ss.version()
                cipher = ss.cipher()
                out["cipher"] = cipher[0] if cipher else None
                out["cipher_bits"] = cipher[2] if cipher else None
                der = ss.getpeercert(binary_form=True)
                chain_len = 1
                if hasattr(ss, "get_unverified_chain"):
                    try:
                        chain = ss.get_unverified_chain()
                        chain_len = len(chain) if chain else 1
                    except Exception:
                        pass
                out["chain_length"] = chain_len
    except Exception as exc:
        out["error"] = str(exc)[:160]
        return out

    out["cert"] = _parse_cert(der)
    out["hostname_match"] = _host_matches(host, out["cert"]) if out["cert"] else None
    # Legacy protocols · only report ones we can actually negotiate.
    weak = []
    for label, ver, sev in _WEAK_PROTOCOLS:
        if _supports_version(host, port, ver):
            weak.append({"protocol": label, "severity": sev})
    out["weak_protocols"] = weak
    return out


def _emit_findings(result: ScanResult, host: str, a: dict) -> None:
    add = result.add_finding
    port = a.get("port", 443)
    target = f"{host}:{port}"
    cert = a.get("cert") or {}

    if cert.get("expired"):
        add(title=f"Expired TLS certificate on {target}", category="tls",
            severity="high", confidence=95, source=SRC, target=target,
            evidence=f"notAfter {cert.get('not_after')} (issuer {cert.get('issuer_cn')})",
            parsed=cert,
            risk="Clients see certificate errors and users are trained to click through them.",
            recommendation="Renew and deploy a valid certificate immediately.",
            tags=["tls", "certificate"], signature=f"cert-expired:{target}")
    elif isinstance(cert.get("days_to_expiry"), int) and \
            0 <= cert["days_to_expiry"] <= config.TLS_EXPIRY_WARN_DAYS:
        add(title=f"TLS certificate expires in {cert['days_to_expiry']} days on {target}",
            category="tls", severity="medium", confidence=90, source=SRC, target=target,
            evidence=f"notAfter {cert.get('not_after')}", parsed=cert,
            risk="An expiring certificate causes an outage the moment it lapses.",
            recommendation="Renew the certificate and automate renewal.",
            tags=["tls", "certificate"], signature=f"cert-expiring:{target}")

    if cert.get("self_signed"):
        add(title=f"Self-signed TLS certificate on {target}", category="tls",
            severity="medium", confidence=85, source=SRC, target=target,
            evidence=f"issuer == subject ({cert.get('subject_cn')})", parsed=cert,
            risk="A self-signed certificate cannot be trusted and enables machine-in-the-middle.",
            recommendation="Use a certificate from a trusted CA.",
            tags=["tls", "certificate"], signature=f"cert-selfsigned:{target}")

    if a.get("hostname_match") is False:
        add(title=f"TLS certificate does not match {host}", category="tls",
            severity="medium", confidence=80, source=SRC, target=target,
            evidence=f"CN={cert.get('subject_cn')} SAN={cert.get('san')}", parsed=cert,
            risk="A name mismatch breaks trust and can indicate a misrouted or shared certificate.",
            recommendation="Serve a certificate whose SAN covers this hostname.",
            tags=["tls", "certificate"], signature=f"cert-mismatch:{target}")

    for w in a.get("weak_protocols", []):
        add(title=f"Legacy protocol {w['protocol']} enabled on {target}",
            category="tls", severity=w["severity"], confidence=88, source=SRC,
            target=target, evidence=f"{w['protocol']} completed a handshake",
            parsed={"protocol": w["protocol"]},
            risk="Obsolete TLS/SSL versions have known cryptographic weaknesses.",
            recommendation="Disable everything below TLS 1.2.",
            tags=["tls", "protocol"], signature=f"weak-proto:{w['protocol']}:{target}")

    cipher = (a.get("cipher") or "").upper()
    if cipher and any(tok in cipher for tok in _WEAK_CIPHER_TOKENS):
        add(title=f"Weak TLS cipher negotiated on {target}", category="tls",
            severity="medium", confidence=80, source=SRC, target=target,
            evidence=f"cipher {a.get('cipher')}", parsed={"cipher": a.get("cipher")},
            risk="A weak cipher undermines confidentiality/integrity of the session.",
            recommendation="Restrict the cipher suite to modern AEAD ciphers.",
            tags=["tls", "cipher"], signature=f"weak-cipher:{target}")

    if isinstance(cert.get("key_bits"), int) and cert.get("key_type") == "RSA" \
            and cert["key_bits"] < 2048:
        add(title=f"Weak RSA key ({cert['key_bits']}-bit) on {target}",
            category="tls", severity="medium", confidence=85, source=SRC, target=target,
            evidence=f"{cert['key_bits']}-bit RSA public key", parsed=cert,
            risk="An undersized RSA key is factorable and no longer considered safe.",
            recommendation="Reissue with a 2048-bit (or larger) key, or an EC key.",
            tags=["tls", "key"], signature=f"weak-key:{target}")


def run(result: ScanResult, *, roots: list[str] | None = None) -> None:
    t0 = time.time()
    if tor.active():
        log.info("skipping TLS review over Tor (raw sockets would bypass the proxy)")
        result.mark_module("tls", "skip", note="not run over Tor")
        return

    targets = _collect_targets(result)
    if not targets:
        result.mark_module("tls", "empty", note="no TLS hosts", duration=0)
        return

    log.info(f"TLS review of {len(targets)} host/port pair"
             f"{'s' if len(targets) != 1 else ''}")
    reviewed = 0
    workers = max(1, min(config.CRAWL_THREADS, len(targets)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_analyze_one, h, p): (h, p) for h, p in targets}
        for fut in concurrent.futures.as_completed(futs):
            host, port = futs[fut]
            try:
                a = fut.result()
            except Exception as exc:
                log.debug(f"{host}:{port}: {exc}")
                continue
            if a.get("error"):
                continue
            sub = result._subdomains.get(host)      # type: ignore[attr-defined]
            if sub is not None:
                sub.setdefault("tls", {})[str(port)] = {
                    k: v for k, v in a.items() if k not in ("host", "port")}
            _emit_findings(result, host, a)
            reviewed += 1

    log.info(f"TLS review complete: {reviewed} endpoint"
             f"{'s' if reviewed != 1 else ''} ({time.time() - t0:.1f}s)")
    result.mark_module("tls", "ok" if reviewed else "empty",
                       note=f"{reviewed} endpoints", duration=time.time() - t0)
