from __future__ import annotations

from pathlib import Path

from certswap.drivers import get_driver
from certswap.drivers.base import TargetContext
from certswap.ingest.pem import parse_pem


def _ctx(dest: Path, **opts: object) -> TargetContext:
    base: dict[str, object] = {"dest": str(dest), "cert_name": "fullchain"}
    base.update(opts)
    return TargetContext(driver="local", identifier=str(dest), options=base)


def test_plan_into_fresh_directory_lists_writes(pem_bundle: Path, tmp_path: Path) -> None:
    cb = parse_pem(pem_bundle)
    ctx = _ctx(tmp_path / "deploy")
    plan = get_driver("local").plan(cb, ctx)
    step_descs = [s.description for s in plan.steps]
    assert "create destination directory" in step_descs
    assert "write cert" in step_descs
    assert "write key" in step_descs
    assert plan.blockers == []


def test_apply_writes_files_with_correct_modes(pem_bundle: Path, tmp_path: Path) -> None:
    cb = parse_pem(pem_bundle)
    dest = tmp_path / "deploy"
    ctx = _ctx(dest)
    result = get_driver("local").apply(cb, ctx)
    assert result.exit_code == 0
    cert_path = dest / "fullchain.pem"
    key_path = dest / "fullchain.key"
    assert cert_path.is_file()
    assert key_path.is_file()
    assert cert_path.stat().st_mode & 0o777 == 0o644
    assert key_path.stat().st_mode & 0o777 == 0o600
    assert result.verify is not None and result.verify.ok


def test_apply_combined_writes_third_file(pem_bundle: Path, tmp_path: Path) -> None:
    cb = parse_pem(pem_bundle)
    dest = tmp_path / "deploy"
    ctx = _ctx(dest, combined=True)
    result = get_driver("local").apply(cb, ctx)
    assert result.exit_code == 0
    combined = dest / "fullchain-combined.pem"
    assert combined.is_file()
    body = combined.read_bytes()
    assert b"-----BEGIN CERTIFICATE-----" in body
    assert b"PRIVATE KEY-----" in body


def test_apply_is_idempotent(pem_bundle: Path, tmp_path: Path) -> None:
    cb = parse_pem(pem_bundle)
    dest = tmp_path / "deploy"
    ctx = _ctx(dest, force=True)
    r1 = get_driver("local").apply(cb, ctx)
    r2 = get_driver("local").apply(cb, ctx)
    assert r1.exit_code == 0 and r2.exit_code == 0
    # Files unchanged in content between the two runs
    cert = dest / "fullchain.pem"
    assert cert.read_bytes().count(b"-----BEGIN CERTIFICATE-----") == 2


def test_plan_blocks_when_dest_is_a_file(pem_bundle: Path, tmp_path: Path) -> None:
    cb = parse_pem(pem_bundle)
    occupied = tmp_path / "deploy"
    occupied.write_text("not a directory")
    ctx = _ctx(occupied)
    plan = get_driver("local").plan(cb, ctx)
    assert plan.is_blocked
    assert any("not a directory" in b for b in plan.blockers)


def test_verify_without_apply_fails(tmp_path: Path) -> None:
    dest = tmp_path / "nothing-here"
    ctx = _ctx(dest)
    result = get_driver("local").verify(ctx)
    assert result.ok is False
    assert any("missing" in (c.detail or "") for c in result.checks)
