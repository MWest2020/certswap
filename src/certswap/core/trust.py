"""Linux trust store discovery.

macOS keychain is intentionally out of scope for v1.
"""

from __future__ import annotations

from pathlib import Path

LINUX_TRUST_STORE_PATHS: tuple[Path, ...] = (
    Path("/etc/ssl/certs/ca-certificates.crt"),  # Debian/Ubuntu
    Path("/etc/pki/tls/certs/ca-bundle.crt"),  # RHEL/Fedora
    Path("/etc/ssl/cert.pem"),  # Alpine
)


class TrustStoreNotFound(RuntimeError):
    """Raised when no system trust store can be located."""


def discover() -> Path:
    """Return the first existing trust store path on the host.

    Raises :class:`TrustStoreNotFound` if none are present.
    """
    for path in LINUX_TRUST_STORE_PATHS:
        if path.is_file():
            return path
    raise TrustStoreNotFound(
        "no Linux trust store found; tried: "
        + ", ".join(str(p) for p in LINUX_TRUST_STORE_PATHS)
    )
