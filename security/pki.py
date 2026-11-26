"""RFC 5280 X509_STRICT Compliant Local PKI Generator (Root CA + SAN TLS Leaf Certificate)."""

from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CERTS_DIR = PROJECT_ROOT / "certs"
CA_CERT_PATH = CERTS_DIR / "comet_ca.pem"
SERVER_CERT_PATH = CERTS_DIR / "comet_server.pem"
SERVER_KEY_PATH = CERTS_DIR / "comet_server_key.pem"


def ensure_tls_certificates(force_regenerate: bool = False) -> Tuple[Path, Path, Path]:
    """Generates an RFC 5280 X509_STRICT compliant ECDSA P-256 Root CA + SAN server cert."""
    if (
        not force_regenerate
        and CA_CERT_PATH.exists()
        and SERVER_CERT_PATH.exists()
        and SERVER_KEY_PATH.exists()
    ):
        return CA_CERT_PATH, SERVER_CERT_PATH, SERVER_KEY_PATH

    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Root CA with SubjectKeyIdentifier & AuthorityKeyIdentifier (Python 3.13 VERIFY_X509_STRICT)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "COMET Enterprise Security CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "COMET Local Root CA"),
        ]
    )
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ca_ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # 2. Server Leaf Certificate with SKI + AKI + KeyUsage + SAN (127.0.0.1, ::1, localhost)
    srv_key = ec.generate_private_key(ec.SECP256R1())
    srv_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "COMET Microservices"),
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
        ]
    )
    srv_ski = x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key())
    san = x509.SubjectAlternativeName(
        [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            x509.IPAddress(ipaddress.IPv6Address("::1")),
        ]
    )
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(srv_subject)
        .issuer_name(ca_subject)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(srv_ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
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
        .add_extension(san, critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    CA_CERT_PATH.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    SERVER_CERT_PATH.write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM))
    SERVER_KEY_PATH.write_bytes(
        srv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return CA_CERT_PATH, SERVER_CERT_PATH, SERVER_KEY_PATH
