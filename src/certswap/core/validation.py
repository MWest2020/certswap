"""Bundle validation: key↔cert match, chain verification, SAN matching."""

from __future__ import annotations

import warnings
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.verification import PolicyBuilder, Store

from certswap.models import CertBundle


def key_matches_cert(key: PrivateKeyTypes, cert: x509.Certificate) -> bool:
    """True when ``key`` and ``cert`` share the same public key.

    Compares the SubjectPublicKeyInfo DER encoding — works for RSA, ECDSA,
    Ed25519, Ed448 without per-algorithm branching.
    """
    key_spki = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert_spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key_spki == cert_spki


def san_matches_host(bundle: CertBundle, host: str) -> bool:
    """True when ``host`` appears in the leaf SubjectAlternativeName list.

    Matches DNS SANs case-insensitively. No wildcard expansion in v1 — a
    wildcard SAN ``*.example.com`` matches ``foo.example.com`` but not
    ``example.com`` or ``a.b.example.com``.
    """
    host_lc = host.lower()
    for san in bundle.sans():
        san_lc = san.lower()
        if san_lc == host_lc:
            return True
        if san_lc.startswith("*."):
            suffix = san_lc[1:]  # ".example.com"
            if host_lc.endswith(suffix) and host_lc.count(".") == san_lc.count("."):
                return True
    return False


def _load_trust_store(path: Path) -> Store:
    pem = path.read_bytes()
    # Some shipped trust stores still contain pre-RFC-5280 CAs with
    # non-positive serial numbers; cryptography warns but accepts them.
    # We don't control the trust store, so we silence that specific
    # warning rather than surface it to every user.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        certs = x509.load_pem_x509_certificates(pem)
    return Store(certs)


def verify_chain(bundle: CertBundle, trust_store: Path) -> bool:
    """True when ``bundle.leaf`` is verifiable against the trust store.

    The intermediates supplied in ``bundle.chain`` are offered as the
    untrusted intermediate pool. A server-style policy (EKU = serverAuth)
    is enforced.
    """
    store = _load_trust_store(trust_store)
    builder = PolicyBuilder().store(store)
    # Pick the first SAN if present; verifier requires a subject hint.
    sans = bundle.sans()
    if sans:
        subject = x509.DNSName(sans[0])
    else:
        # No SAN — fall back to subject CN. Verification may still fail
        # under modern policy, but we want a deterministic input.
        cn = bundle.subject_cn() or "unknown"
        subject = x509.DNSName(cn)
    verifier = builder.build_server_verifier(subject)
    try:
        verifier.verify(bundle.leaf, bundle.chain)
        return True
    except Exception:
        # Verification failures are expected for self-signed / test bundles.
        return False
