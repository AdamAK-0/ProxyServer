"""Educational HTTPS MITM certificate authority helpers.

Contributor: Adam - local CA and per-host certificate generation for opt-in MITM.
External code: uses the third-party ``cryptography`` package when MITM mode is enabled.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock


class MitmDependencyError(RuntimeError):
    """Raised when optional MITM dependencies are not installed."""


class CertificateAuthority:
    """Creates a local root CA and leaf certificates for intercepted hosts."""

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.certs_dir = base_dir / "certs"
        self.ca_key_path = base_dir / "ca.key.pem"
        self.ca_cert_path = base_dir / "ca.cert.pem"
        self._lock = Lock()
        self._crypto = self._load_crypto()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_ca()

    def certificate_for_host(self, host: str) -> tuple[Path, Path]:
        """Return cert/key paths for a target host, generating them if needed."""

        safe_name = self._safe_name(host)
        cert_path = self.certs_dir / f"{safe_name}.cert.pem"
        key_path = self.certs_dir / f"{safe_name}.key.pem"
        with self._lock:
            if self._leaf_is_valid(cert_path):
                return cert_path, key_path
            self._generate_leaf(host, cert_path, key_path)
            return cert_path, key_path

    def _ensure_ca(self) -> None:
        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            return

        x509 = self._crypto["x509"]
        NameOID = self._crypto["NameOID"]
        hashes = self._crypto["hashes"]
        rsa = self._crypto["rsa"]
        serialization = self._crypto["serialization"]

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "LB"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSC 430 Educational Proxy"),
                x509.NameAttribute(NameOID.COMMON_NAME, "CSC 430 Proxy Local Root CA"),
            ]
        )
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )

        self.ca_key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def _generate_leaf(self, host: str, cert_path: Path, key_path: Path) -> None:
        x509 = self._crypto["x509"]
        NameOID = self._crypto["NameOID"]
        ExtendedKeyUsageOID = self._crypto["ExtendedKeyUsageOID"]
        hashes = self._crypto["hashes"]
        rsa = self._crypto["rsa"]
        serialization = self._crypto["serialization"]
        load_pem_private_key = self._crypto["load_pem_private_key"]
        load_pem_x509_certificate = self._crypto["load_pem_x509_certificate"]

        ca_key = load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
        ca_cert = load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSC 430 Educational Proxy"),
                x509.NameAttribute(NameOID.COMMON_NAME, host),
            ]
        )
        alt_names = [self._subject_alt_name(host)]
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def _leaf_is_valid(self, cert_path: Path) -> bool:
        if not cert_path.exists():
            return False
        try:
            cert = self._crypto["load_pem_x509_certificate"](cert_path.read_bytes())
        except Exception:
            return False
        expires_at = getattr(cert, "not_valid_after_utc", cert.not_valid_after.replace(tzinfo=timezone.utc))
        return expires_at > datetime.now(timezone.utc) + timedelta(days=1)

    def _subject_alt_name(self, host: str):
        x509 = self._crypto["x509"]
        try:
            return x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            return x509.DNSName(host)

    @staticmethod
    def _safe_name(host: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", host)[:180] or "unknown-host"

    @staticmethod
    def _load_crypto() -> dict[str, object]:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            from cryptography.x509 import load_pem_x509_certificate
            from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        except ImportError as exc:
            raise MitmDependencyError(
                "MITM mode requires the optional dependency 'cryptography'. "
                "Install it with: python -m pip install -r requirements.txt"
            ) from exc
        return {
            "x509": x509,
            "hashes": hashes,
            "serialization": serialization,
            "rsa": rsa,
            "load_pem_private_key": load_pem_private_key,
            "load_pem_x509_certificate": load_pem_x509_certificate,
            "ExtendedKeyUsageOID": ExtendedKeyUsageOID,
            "NameOID": NameOID,
        }
