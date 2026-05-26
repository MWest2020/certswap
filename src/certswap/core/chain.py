"""Chain ordering, gap detection, and AIA-walk completion."""

from __future__ import annotations

import logging
from typing import Final

import httpx
from cryptography import x509
from cryptography.x509 import AuthorityInformationAccess
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from certswap.models import CertBundle

logger = logging.getLogger(__name__)

AIA_TIMEOUT_SECONDS: Final = 10.0
AIA_MAX_HOPS: Final = 5  # safety bound to avoid runaway chains
AIA_MAX_BYTES: Final = 256 * 1024  # any single intermediate fits well under this
AIA_ALLOWED_SCHEMES: Final = frozenset({"http", "https"})


def order_chain(
    leaf: x509.Certificate, candidates: list[x509.Certificate]
) -> list[x509.Certificate]:
    """Return ``candidates`` ordered from leaf-issuer toward the root.

    The leaf itself is never included in the returned list. Certificates
    in ``candidates`` that cannot be linked into the chain are dropped
    (with a debug log), not silently re-included.
    """
    by_subject: dict[bytes, x509.Certificate] = {
        c.subject.public_bytes(): c for c in candidates if c != leaf
    }
    ordered: list[x509.Certificate] = []
    current_issuer = leaf.issuer.public_bytes()
    seen: set[bytes] = set()
    while current_issuer in by_subject:
        cert = by_subject[current_issuer]
        subj = cert.subject.public_bytes()
        if subj in seen:
            break  # cycle guard
        seen.add(subj)
        ordered.append(cert)
        if cert.issuer.public_bytes() == subj:
            break  # self-signed root reached
        current_issuer = cert.issuer.public_bytes()
    dropped = len(by_subject) - len(ordered)
    if dropped:
        logger.debug("order_chain: dropped %d unlinkable cert(s)", dropped)
    return ordered


def chain_is_complete(chain: list[x509.Certificate]) -> bool:
    """True when the last cert in ``chain`` is self-signed (root reached)."""
    if not chain:
        return False
    tail = chain[-1]
    return tail.issuer.public_bytes() == tail.subject.public_bytes()


def _aia_ca_issuer_urls(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
    except x509.ExtensionNotFound:
        return []
    aia = ext.value
    if not isinstance(aia, AuthorityInformationAccess):
        return []
    urls: list[str] = []
    for access in aia:
        if access.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            loc = access.access_location
            if isinstance(loc, x509.UniformResourceIdentifier):
                urls.append(loc.value)
    return urls


def _fetch_cert(url: str, *, client: httpx.Client) -> x509.Certificate | None:
    # AIA URLs come from the bundle itself, which the operator already
    # decided to trust enough to ingest — but defend against pathological
    # certs anyway: cap size, restrict to http(s), and reject redirects.
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError):
        logger.warning("AIA URL malformed: %r", url)
        return None
    if parsed.scheme not in AIA_ALLOWED_SCHEMES:
        logger.warning("AIA URL has disallowed scheme: %r", url)
        return None

    try:
        with client.stream("GET", url, timeout=AIA_TIMEOUT_SECONDS) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > AIA_MAX_BYTES:
                    logger.warning(
                        "AIA response from %s exceeds %d bytes; refused",
                        url,
                        AIA_MAX_BYTES,
                    )
                    return None
                chunks.append(chunk)
            data = b"".join(chunks)
    except httpx.HTTPError as exc:
        logger.warning("AIA fetch failed for %s: %s", url, exc)
        return None

    if data.lstrip().startswith(b"-----BEGIN"):
        try:
            return x509.load_pem_x509_certificate(data)
        except ValueError as exc:
            logger.warning("AIA response from %s is not valid PEM: %s", url, exc)
            return None
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        logger.warning("AIA response from %s is not valid DER: %s", url, exc)
        return None


def complete_chain(
    bundle: CertBundle, *, fetch: bool = False
) -> CertBundle:
    """Return ``bundle`` with chain ordered, optionally AIA-walked.

    When ``fetch`` is False, only reorders the existing chain. When True,
    fetches up to :data:`AIA_MAX_HOPS` intermediates via the
    AuthorityInformationAccess extension.
    """
    ordered = order_chain(bundle.leaf, bundle.chain)
    if not fetch or chain_is_complete(ordered):
        return bundle.model_copy(update={"chain": ordered})

    # follow_redirects=False: AIA redirects are vanishingly rare and a
    # redirect target could escape the scheme guard above.
    with httpx.Client(follow_redirects=False) as client:
        for _ in range(AIA_MAX_HOPS):
            tail = ordered[-1] if ordered else bundle.leaf
            if tail.issuer.public_bytes() == tail.subject.public_bytes():
                break  # root reached
            urls = _aia_ca_issuer_urls(tail)
            if not urls:
                break
            fetched: x509.Certificate | None = None
            for url in urls:
                fetched = _fetch_cert(url, client=client)
                if fetched is not None:
                    break
            if fetched is None:
                break
            if any(c == fetched for c in ordered):
                break  # already have it; AIA loop
            ordered.append(fetched)
    return bundle.model_copy(update={"chain": ordered})
