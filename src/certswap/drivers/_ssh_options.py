"""Options + planned-file enumeration for the ssh driver."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization

from certswap.drivers.base import TargetContext
from certswap.models import CertBundle


@dataclass(frozen=True)
class SshOptions:
    host: str
    cert_dest: str | None
    key_dest: str | None
    chain_dest: str | None
    combined_dest: str | None
    mode_cert: int = 0o644
    mode_key: int = 0o600
    owner: str | None = None
    group: str | None = None
    reload_cmd: str | None = None
    pre_check_cmd: str | None = None
    post_check_cmd: str | None = None

    @classmethod
    def from_context(cls, ctx: TargetContext) -> SshOptions:
        o: dict[str, Any] = ctx.options
        host = o.get("host")
        if not host:
            raise ValueError("ssh driver requires `host` in TargetContext.options")
        return cls(
            host=str(host),
            cert_dest=_opt(o.get("cert_dest")),
            key_dest=_opt(o.get("key_dest")),
            chain_dest=_opt(o.get("chain_dest")),
            combined_dest=_opt(o.get("combined_dest")),
            mode_cert=int(o.get("mode_cert") or 0o644),
            mode_key=int(o.get("mode_key") or 0o600),
            owner=_opt(o.get("owner")),
            group=_opt(o.get("group")),
            reload_cmd=_opt(o.get("reload_cmd")),
            pre_check_cmd=_opt(o.get("pre_check_cmd")),
            post_check_cmd=_opt(o.get("post_check_cmd")),
        )


def _opt(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


def planned_files(
    bundle: CertBundle, opts: SshOptions
) -> list[tuple[str, str, int, bytes]]:
    """Return ordered (label, remote_path, mode, payload) tuples for apply."""
    items: list[tuple[str, str, int, bytes]] = []
    if opts.cert_dest:
        items.append(("cert", opts.cert_dest, opts.mode_cert, bundle.to_pem_fullchain()))
    if opts.key_dest:
        items.append(("key", opts.key_dest, opts.mode_key, bundle.to_pem_key()))
    if opts.chain_dest:
        chain_pem = b"".join(
            c.public_bytes(serialization.Encoding.PEM) for c in bundle.chain
        )
        items.append(("chain", opts.chain_dest, opts.mode_cert, chain_pem))
    if opts.combined_dest:
        items.append(
            (
                "combined",
                opts.combined_dest,
                opts.mode_key,
                bundle.to_pem_fullchain() + bundle.to_pem_key(),
            )
        )
    return items


def verify_targets(opts: SshOptions) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if opts.cert_dest:
        out.append(("cert", opts.cert_dest))
    if opts.key_dest:
        out.append(("key", opts.key_dest))
    if opts.chain_dest:
        out.append(("chain", opts.chain_dest))
    if opts.combined_dest:
        out.append(("combined", opts.combined_dest))
    return out


def remote_dirname(remote_path: str) -> str:
    if "/" not in remote_path:
        return "."
    parent = remote_path.rsplit("/", 1)[0]
    return parent or "/"
