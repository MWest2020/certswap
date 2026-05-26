"""Shared test fixtures: a freshly-generated test CA, intermediate, and leaf.

Everything is generated in-process so the repo stays free of binary fixture
files. The CA is reused across the test session.
"""

from __future__ import annotations

import io
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class TestPKI:
    ca_key: rsa.RSAPrivateKey
    ca_cert: x509.Certificate
    intermediate_key: rsa.RSAPrivateKey
    intermediate_cert: x509.Certificate
    leaf_key: rsa.RSAPrivateKey
    leaf_cert: x509.Certificate
    leaf_san: str


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def _make_ca(name: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - timedelta(days=1))
        .not_valid_after(_now() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_intermediate(
    ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate, name: str
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - timedelta(days=1))
        .not_valid_after(_now() + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(
    issuer_key: rsa.RSAPrivateKey, issuer_cert: x509.Certificate, san: str
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, san)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - timedelta(days=1))
        .not_valid_after(_now() + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )
    return key, cert


@pytest.fixture(scope="session")
def pki() -> TestPKI:
    ca_key, ca_cert = _make_ca("certswap test CA")
    int_key, int_cert = _make_intermediate(ca_key, ca_cert, "certswap test intermediate")
    leaf_san = "test.certswap.example"
    leaf_key, leaf_cert = _make_leaf(int_key, int_cert, leaf_san)
    return TestPKI(
        ca_key=ca_key,
        ca_cert=ca_cert,
        intermediate_key=int_key,
        intermediate_cert=int_cert,
        leaf_key=leaf_key,
        leaf_cert=leaf_cert,
        leaf_san=leaf_san,
    )


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture
def pem_bundle(pki: TestPKI, tmp_path: Path) -> Path:
    bundle = (
        _pem_cert(pki.leaf_cert)
        + _pem_cert(pki.intermediate_cert)
        + _pem_key(pki.leaf_key)
    )
    path = tmp_path / "bundle.pem"
    path.write_bytes(bundle)
    return path


@pytest.fixture
def pem_bundle_leaf_only(pki: TestPKI, tmp_path: Path) -> Path:
    bundle = _pem_cert(pki.leaf_cert) + _pem_key(pki.leaf_key)
    path = tmp_path / "leaf-only.pem"
    path.write_bytes(bundle)
    return path


@pytest.fixture
def pfx_bundle(pki: TestPKI, tmp_path: Path) -> Path:
    data = pkcs12.serialize_key_and_certificates(
        name=b"certswap-test",
        key=pki.leaf_key,
        cert=pki.leaf_cert,
        cas=[pki.intermediate_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(b"hunter2"),
    )
    path = tmp_path / "bundle.pfx"
    path.write_bytes(data)
    return path


@pytest.fixture
def legacy_pfx_bundle(pki: TestPKI, tmp_path: Path) -> Path:
    """A legacy (RC2-40) PKCS#12 produced via `openssl pkcs12 -export -legacy`.

    Skips if openssl is missing or its legacy provider is unavailable.
    """
    if shutil.which("openssl") is None:
        pytest.skip("openssl not on PATH")
    cert_pem = _pem_cert(pki.leaf_cert) + _pem_cert(pki.intermediate_cert)
    key_pem = _pem_key(pki.leaf_key)
    with (
        tempfile.NamedTemporaryFile(suffix=".pem") as cert_f,
        tempfile.NamedTemporaryFile(suffix=".pem") as key_f,
    ):
        cert_f.write(cert_pem)
        cert_f.flush()
        key_f.write(key_pem)
        key_f.flush()
        result = subprocess.run(
            [
                "openssl",
                "pkcs12",
                "-export",
                "-legacy",
                "-in",
                cert_f.name,
                "-inkey",
                key_f.name,
                "-passout",
                "stdin",
            ],
            input=b"hunter2\n",
            capture_output=True,
            check=False,
        )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        pytest.skip(f"openssl legacy export unavailable: {stderr}")
    path = tmp_path / "legacy.pfx"
    path.write_bytes(result.stdout)
    return path


@pytest.fixture
def pkcs7_chain_with_key(pki: TestPKI, tmp_path: Path) -> tuple[Path, Path]:
    """DER-encoded PKCS#7 (.p7b) with leaf + intermediate, plus a separate key file."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl not on PATH")
    cert_pem = _pem_cert(pki.leaf_cert) + _pem_cert(pki.intermediate_cert)
    with tempfile.NamedTemporaryFile(suffix=".pem") as cert_f:
        cert_f.write(cert_pem)
        cert_f.flush()
        result = subprocess.run(
            [
                "openssl",
                "crl2pkcs7",
                "-nocrl",
                "-certfile",
                cert_f.name,
                "-outform",
                "DER",
            ],
            capture_output=True,
            check=False,
        )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        pytest.skip(f"openssl crl2pkcs7 unavailable: {stderr}")
    p7_path = tmp_path / "chain.p7b"
    p7_path.write_bytes(result.stdout)
    key_path = tmp_path / "leaf.key"
    key_path.write_bytes(_pem_key(pki.leaf_key))
    return p7_path, key_path


@pytest.fixture
def separate_files_dir(pki: TestPKI, tmp_path: Path) -> Path:
    d = tmp_path / "letsencrypt-style"
    d.mkdir()
    (d / "fullchain.pem").write_bytes(
        _pem_cert(pki.leaf_cert) + _pem_cert(pki.intermediate_cert)
    )
    (d / "privkey.pem").write_bytes(_pem_key(pki.leaf_key))
    return d


@pytest.fixture
def zip_bundle(pki: TestPKI, tmp_path: Path) -> Path:
    bundle = (
        _pem_cert(pki.leaf_cert)
        + _pem_cert(pki.intermediate_cert)
        + _pem_key(pki.leaf_key)
    )
    path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("bundle.pem", bundle)
    return path


def _tar_add_bytes(tf: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    tf.addfile(info, fileobj=io.BytesIO(data))


@pytest.fixture
def tar_gz_bundle(pki: TestPKI, tmp_path: Path) -> Path:
    cert_data = _pem_cert(pki.leaf_cert) + _pem_cert(pki.intermediate_cert)
    key_data = _pem_key(pki.leaf_key)
    path = tmp_path / "bundle.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        _tar_add_bytes(tf, "fullchain.pem", cert_data)
        _tar_add_bytes(tf, "privkey.pem", key_data)
    return path
