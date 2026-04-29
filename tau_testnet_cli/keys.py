"""Key generation and on-disk key store for the Tau Testnet CLI.

Reuses ``wallet._parse_privkey`` and ``wallet._normalize_sk_material`` so the
on-the-wire key format stays identical to the existing console wallet.

Storage layout (default ``~/.tau-testnet/keys/<name>.json``):

    {
      "version": 1,
      "name": "alice",
      "created_at": "2026-04-27T00:00:00Z",
      "private_key_hex": "...",
      "public_key_hex": "..."
    }

Files are chmod 0600 on POSIX. ``list_keys`` and ``load_key`` for listing
purposes only ever expose ``name`` / ``public_key_hex`` / ``created_at`` —
they never return private material to the caller.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from py_ecc.bls import G2Basic

from wallet import _normalize_sk_material, _parse_privkey

logger = logging.getLogger(__name__)


KEY_DIR_DEFAULT = Path.home() / ".tau-testnet" / "keys"
KEY_FILE_VERSION = 1


def generate_keypair() -> dict:
    """Generate a fresh BLS12-381 keypair via the same KDF wallet.py uses.

    Returns ``{'private_key_hex', 'public_key_hex', 'private_key_int'}``.
    """
    ikm = secrets.token_bytes(32)
    sk_int, sk_bytes = _normalize_sk_material(G2Basic.KeyGen(ikm))
    pk = G2Basic.SkToPk(sk_int)
    return {
        "private_key_hex": sk_bytes.hex(),
        "public_key_hex": pk.hex(),
        "private_key_int": sk_int,
    }


def parse_private_key(value: str) -> bytes:
    """Parse a private key from hex (with or without 0x) or decimal."""
    return _parse_privkey(value)


def public_key_from_private(value: str) -> str:
    """Derive the 96-character hex public key from a private key string."""
    raw = parse_private_key(value)
    sk_int = int.from_bytes(raw, "big")
    return G2Basic.SkToPk(sk_int).hex()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _key_path(name: str, key_dir: Path) -> Path:
    if not name or "/" in name or "\\" in name or name in (".", ".."):
        raise ValueError(f"invalid key name: {name!r}")
    return key_dir / f"{name}.json"


def _resolve_key_dir(key_dir: Path | None) -> Path:
    return key_dir if key_dir is not None else KEY_DIR_DEFAULT


def save_key(
    name: str,
    key_dir: Path | None = None,
    *,
    privkey: str | None = None,
    overwrite: bool = False,
) -> Path:
    """Generate or import a keypair and save it to ``<key_dir>/<name>.json``.

    If ``privkey`` is None, a fresh keypair is generated. Otherwise the
    supplied private key is parsed via :func:`parse_private_key`, the
    public key is derived from it, and both are saved.

    Raises ``FileExistsError`` if the destination already exists and
    ``overwrite`` is False.
    """
    key_dir = _resolve_key_dir(key_dir)
    file_path = _key_path(name, key_dir)
    if file_path.exists() and not overwrite:
        raise FileExistsError(f"key already exists: {file_path}")

    if privkey is None:
        kp = generate_keypair()
        priv_hex = kp["private_key_hex"]
        pub_hex = kp["public_key_hex"]
    else:
        raw = parse_private_key(privkey)
        sk_int = int.from_bytes(raw, "big")
        priv_hex = raw.hex()
        pub_hex = G2Basic.SkToPk(sk_int).hex()

    record = {
        "version": KEY_FILE_VERSION,
        "name": name,
        "created_at": _utc_now_iso(),
        "private_key_hex": priv_hex,
        "public_key_hex": pub_hex,
    }

    key_dir.mkdir(parents=True, exist_ok=True)
    file_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(file_path, 0o600)
    except OSError:
        # Non-POSIX (Windows) — silently skip; perms are best-effort.
        pass
    return file_path


def load_key(name: str, key_dir: Path | None = None) -> dict:
    """Load a key file. Warns if file permissions are broader than 0600."""
    key_dir = _resolve_key_dir(key_dir)
    file_path = _key_path(name, key_dir)
    if not file_path.exists():
        raise FileNotFoundError(f"key not found: {file_path}")

    try:
        mode = os.stat(file_path).st_mode & 0o777
        if mode & 0o077:
            logger.warning(
                "key file %s has broader permissions than 0600 (got 0o%03o); "
                "consider `chmod 600 %s`",
                file_path,
                mode,
                file_path,
            )
    except OSError:
        pass

    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"key file {file_path} is not valid JSON: {exc}") from exc


def list_keys(key_dir: Path | None = None) -> list[dict]:
    """Return public-only metadata for every key in ``key_dir``.

    Never includes ``private_key_hex``. Files that fail to parse are skipped.
    """
    key_dir = _resolve_key_dir(key_dir)
    if not key_dir.exists():
        return []

    out: list[dict] = []
    for path in sorted(key_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        out.append(
            {
                "name": data.get("name", path.stem),
                "public_key_hex": data.get("public_key_hex"),
                "created_at": data.get("created_at"),
            }
        )
    return out


def delete_key(name: str, key_dir: Path | None = None) -> Path:
    """Delete a key file. Returns the deleted path."""
    key_dir = _resolve_key_dir(key_dir)
    file_path = _key_path(name, key_dir)
    if not file_path.exists():
        raise FileNotFoundError(f"key not found: {file_path}")
    file_path.unlink()
    return file_path
