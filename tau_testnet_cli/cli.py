"""Tau Testnet developer CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from importlib import metadata
from pathlib import Path
from typing import Any, Callable

# Silence chatty INFO logs emitted at import time by network/commands modules
# before tx_mod / keys_mod are loaded. _configure_logging() upgrades to DEBUG
# when --verbose is set.
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logging.getLogger().setLevel(logging.WARNING)

from tau_testnet_cli import __version__
from tau_testnet_cli import docker as docker_mod
from tau_testnet_cli import keys as keys_mod
from tau_testnet_cli import rpc as rpc_mod
from tau_testnet_cli import tx as tx_mod
from tau_testnet_cli.formatting import (
    parse_json_response,
    print_error,
    print_result,
)

EXIT_OK = 0
EXIT_APP_ERROR = 1
EXIT_USAGE = 2
EXIT_NETWORK = 3
EXIT_LOCAL = 4

DEFAULT_HOST_FALLBACK = "127.0.0.1"
DEFAULT_PORT_FALLBACK = 65432
DEFAULT_TIMEOUT = rpc_mod.DEFAULT_TIMEOUT


def _default_host() -> str:
    try:
        import config

        host = getattr(config, "HOST", None)
    except Exception:
        host = None
    # 0.0.0.0 is a server bind-all sentinel; for a client we want 127.0.0.1.
    if not host or host in ("0.0.0.0", "::"):
        return DEFAULT_HOST_FALLBACK
    return host


def _default_port() -> int:
    try:
        import config

        return int(getattr(config, "PORT", DEFAULT_PORT_FALLBACK))
    except Exception:
        return DEFAULT_PORT_FALLBACK


def _resolved_version() -> str:
    try:
        return metadata.version("tau-testnet")
    except metadata.PackageNotFoundError:
        return __version__


def _send(args: argparse.Namespace, command: str) -> str:
    return rpc_mod.send_command(
        command,
        args.host,
        args.port,
        timeout=args.timeout,
    )


# --------------------------------------------------------------------------- #
# Command handles
# --------------------------------------------------------------------------- #


def cmd_version(args: argparse.Namespace) -> int:
    if args.json:
        print_result({"version": _resolved_version()}, json_mode=True)
    else:
        print(_resolved_version())
    return EXIT_OK


def cmd_ping(args: argparse.Namespace) -> int:
    response = rpc_mod.handshake(args.host, args.port, timeout=args.timeout)
    if args.json:
        print_result({"handshake": response}, json_mode=True)
    else:
        print(response)
    return EXIT_APP_ERROR if rpc_mod.is_error_response(response) else EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    """Best-effort status: handshake + gettimestamp + getmempool. Partial OK."""
    parts: dict[str, Any] = {}

    def _try(label: str, command_str: str) -> None:
        try:
            parts[label] = parse_json_response(_send(args, command_str))
        except rpc_mod.RpcError as exc:
            parts[label] = {"error": str(exc)}

    try:
        parts["handshake"] = rpc_mod.handshake(
            args.host, args.port, timeout=args.timeout
        )
    except rpc_mod.RpcError as exc:
        parts["handshake"] = {"error": str(exc)}

    _try("timestamp", "gettimestamp")
    _try("mempool", "getmempool")

    if args.json:
        print_result(parts, json_mode=True)
    else:
        for label, value in parts.items():
            if isinstance(value, dict) and "error" in value:
                print(f"{label}: ERROR {value['error']}")
            elif isinstance(value, str):
                print(f"{label}: {value}")
            else:
                print(f"{label}: {json.dumps(value)}")

    if not isinstance(parts["handshake"], str) or rpc_mod.is_error_response(
        parts["handshake"]
    ):
        return EXIT_APP_ERROR
    return EXIT_OK


def cmd_rpc(args: argparse.Namespace) -> int:
    response = _send(args, args.command)
    if args.json:
        print_result({"response": parse_json_response(response)}, json_mode=True)
    else:
        print(response)
    return EXIT_APP_ERROR if rpc_mod.is_error_response(response) else EXIT_OK


def _simple_query(args: argparse.Namespace, command: str) -> int:
    response = _send(args, command)
    if rpc_mod.is_error_response(response):
        if args.json:
            print_result({"error": response}, json_mode=True)
        else:
            print(response)
        return EXIT_APP_ERROR
    if args.json:
        print_result(parse_json_response(response), json_mode=True)
    else:
        print(response)
    return EXIT_OK


def cmd_balance(args: argparse.Namespace) -> int:
    return _simple_query(args, f"getbalance {args.address}")


def cmd_sequence(args: argparse.Namespace) -> int:
    return _simple_query(args, f"getsequence {args.address}")


def cmd_history(args: argparse.Namespace) -> int:
    return _simple_query(args, f"history {args.address}")


def cmd_mempool(args: argparse.Namespace) -> int:
    return _simple_query(args, "getmempool")


def cmd_blocks(args: argparse.Namespace) -> int:
    cmd = "getblocks"
    if args.limit is not None:
        cmd = f"{cmd} {args.limit}"
    return _simple_query(args, cmd)


def cmd_accounts(args: argparse.Namespace) -> int:
    return _simple_query(args, "getallaccounts")


def cmd_tau_state(args: argparse.Namespace) -> int:
    return _simple_query(args, "gettaustate")


def cmd_governance(args: argparse.Namespace) -> int:
    return _simple_query(args, "getgovernance")


def cmd_update_id(args: argparse.Namespace) -> int:
    try:
        payload_obj = _load_json_payload(args)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    compact = json.dumps(payload_obj, separators=(",", ":"))
    return _simple_query(args, f"getupdateid {compact}")


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


class _PayloadError(Exception):
    """Local file/JSON parsing error — maps to exit code 4."""


def _load_json_payload(args: argparse.Namespace) -> Any:
    """Load JSON from --file or --json (mutually-exclusive group)."""
    if args.file:
        try:
            text = Path(args.file).read_text(encoding="utf-8")
        except OSError as exc:
            raise _PayloadError(f"could not read --file: {exc}") from exc
    else:
        text = args.json_payload
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise _PayloadError(f"invalid JSON: {exc}") from exc


def _resolve_signing_key(args: argparse.Namespace) -> tuple[int, str]:
    """Return (private_key_int, public_key_hex) from --key NAME or --privkey HEX."""
    if getattr(args, "privkey", None):
        priv_hex = args.privkey
    elif getattr(args, "key", None):
        record = keys_mod.load_key(args.key)
        priv_hex = record["private_key_hex"]
    else:
        raise _PayloadError("--key or --privkey is required")

    raw = keys_mod.parse_private_key(priv_hex)
    sk_int = int.from_bytes(raw, "big")
    from py_ecc.bls import G2Basic

    pub_hex = G2Basic.SkToPk(sk_int).hex()
    return sk_int, pub_hex


def _confirm_destructive(prompt: str, *, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        return False
    try:
        answer = input(prompt).strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


# --------------------------------------------------------------------------- #
# Keys handlers
# --------------------------------------------------------------------------- #


def cmd_keys_new(args: argparse.Namespace) -> int:
    kp = keys_mod.generate_keypair()
    if args.json:
        print_result(
            {
                "private_key_hex": kp["private_key_hex"],
                "public_key_hex": kp["public_key_hex"],
            },
            json_mode=True,
        )
    else:
        print(f"Private Key (hex): {kp['private_key_hex']}")
        print(f"Public Key  (hex): {kp['public_key_hex']}")
    return EXIT_OK


def cmd_keys_pub(args: argparse.Namespace) -> int:
    pub = keys_mod.public_key_from_private(args.privkey)
    if args.json:
        print_result({"public_key_hex": pub}, json_mode=True)
    else:
        print(pub)
    return EXIT_OK


def cmd_keys_save(args: argparse.Namespace) -> int:
    try:
        path = keys_mod.save_key(args.name, privkey=args.privkey)
    except FileExistsError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    record = keys_mod.load_key(args.name)
    pub = record.get("public_key_hex", "")
    if args.json:
        print_result(
            {
                "name": args.name,
                "path": str(path),
                "public_key_hex": pub,
                "imported": args.privkey is not None,
            },
            json_mode=True,
        )
    else:
        action = "Imported" if args.privkey else "Saved"
        print(f"{action} key '{args.name}' → {path}")
        print(f"Public Key (hex): {pub}")
    return EXIT_OK


def cmd_keys_list(args: argparse.Namespace) -> int:
    entries = keys_mod.list_keys()
    if args.json:
        print_result(entries, json_mode=True)
        return EXIT_OK
    if not entries:
        print("(no keys)")
        return EXIT_OK
    for entry in entries:
        print(
            f"{entry['name']}\t{entry.get('public_key_hex', '')}"
            f"\t{entry.get('created_at', '')}"
        )
    return EXIT_OK


def cmd_keys_show(args: argparse.Namespace) -> int:
    try:
        record = keys_mod.load_key(args.name)
    except FileNotFoundError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    if args.private:
        if args.json:
            print_result(
                {
                    "name": record.get("name"),
                    "private_key_hex": record.get("private_key_hex"),
                    "public_key_hex": record.get("public_key_hex"),
                    "created_at": record.get("created_at"),
                },
                json_mode=True,
            )
        else:
            print(f"Private Key (hex): {record.get('private_key_hex')}")
            print(f"Public Key  (hex): {record.get('public_key_hex')}")
        return EXIT_OK
    # Public-only output.
    if args.json:
        print_result(
            {
                "name": record.get("name"),
                "public_key_hex": record.get("public_key_hex"),
                "created_at": record.get("created_at"),
            },
            json_mode=True,
        )
    else:
        print(record.get("public_key_hex", ""))
    return EXIT_OK


def cmd_keys_delete(args: argparse.Namespace) -> int:
    name = args.name
    if not _confirm_destructive(
        f"Delete key '{name}'? [y/N]: ", assume_yes=args.yes
    ):
        if args.yes:  # pragma: no cover — unreachable
            return EXIT_LOCAL
        if sys.stdin.isatty():
            print("aborted")
            return EXIT_LOCAL
        print_error(
            f"refusing to delete key '{name}' without --yes (non-interactive stdin)"
        )
        return EXIT_LOCAL
    try:
        path = keys_mod.delete_key(name)
    except FileNotFoundError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    if args.json:
        print_result({"deleted": str(path)}, json_mode=True)
    else:
        print(f"deleted {path}")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# Tx handlers
# --------------------------------------------------------------------------- #


def cmd_tx_send(args: argparse.Namespace) -> int:
    try:
        sk_int, sender_pubkey = _resolve_signing_key(args)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL

    try:
        operations = tx_mod.assemble_operations(
            sender_pubkey=sender_pubkey,
            to=args.to,
            amount=args.amount,
            transfers=args.transfer,
            rule_file=args.rule_file,
            operations_json=args.operations_json,
        )
    except (ValueError, OSError) as exc:
        print_error(str(exc))
        return EXIT_LOCAL

    try:
        sequence_number = tx_mod.get_sequence(
            sender_pubkey,
            host=args.host,
            port=args.port,
            timeout=args.timeout,
        )
    except RuntimeError as exc:
        print_error(str(exc))
        return EXIT_APP_ERROR

    payload = tx_mod.build_and_sign_user_tx(
        private_key=sk_int,
        sender_pubkey=sender_pubkey,
        sequence_number=sequence_number,
        operations=operations,
        fee_limit=args.fee,
        expiry_seconds=args.expiry,
    )

    response = tx_mod.submit_tx(
        payload, host=args.host, port=args.port, timeout=args.timeout
    )

    if args.json:
        print_result(
            {
                "sender_pubkey": sender_pubkey,
                "sequence_number": sequence_number,
                "submitted": payload,
                "response": parse_json_response(response),
            },
            json_mode=True,
        )
    else:
        print(response)

    return EXIT_APP_ERROR if rpc_mod.is_error_response(response) else EXIT_OK


def cmd_tx_raw_sign(args: argparse.Namespace) -> int:
    try:
        text = Path(args.payload).read_text(encoding="utf-8")
    except OSError as exc:
        print_error(f"could not read --payload: {exc}")
        return EXIT_LOCAL
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        print_error(f"--payload is not valid JSON: {exc}")
        return EXIT_LOCAL
    if not isinstance(payload, dict):
        print_error("--payload must be a JSON object")
        return EXIT_LOCAL

    try:
        signed = tx_mod.sign_tx(payload, args.privkey)
    except (ValueError, TypeError) as exc:
        print_error(str(exc))
        return EXIT_LOCAL

    if args.json:
        print_result(signed, json_mode=True)
    else:
        print(json.dumps(signed, separators=(",", ":")))
    return EXIT_OK


def cmd_tx_raw_submit(args: argparse.Namespace) -> int:
    try:
        text = Path(args.file).read_text(encoding="utf-8")
    except OSError as exc:
        print_error(f"could not read --file: {exc}")
        return EXIT_LOCAL
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        print_error(f"--file is not valid JSON: {exc}")
        return EXIT_LOCAL
    if not isinstance(payload, dict):
        print_error("--file must be a JSON object")
        return EXIT_LOCAL

    response = tx_mod.submit_tx(
        payload, host=args.host, port=args.port, timeout=args.timeout
    )

    if args.json:
        print_result(
            {"submitted": payload, "response": parse_json_response(response)},
            json_mode=True,
        )
    else:
        print(response)
    return EXIT_APP_ERROR if rpc_mod.is_error_response(response) else EXIT_OK


# --------------------------------------------------------------------------- #
# Governance handlers
# --------------------------------------------------------------------------- #


def cmd_gov_list(args: argparse.Namespace) -> int:
    return _simple_query(args, "getgovernance")


def cmd_gov_update_id(args: argparse.Namespace) -> int:
    return cmd_update_id(args)


def cmd_gov_propose(args: argparse.Namespace) -> int:
    try:
        sk_int, sender_pubkey = _resolve_signing_key(args)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL

    try:
        text = Path(args.file).read_text(encoding="utf-8")
    except OSError as exc:
        print_error(f"could not read --file: {exc}")
        return EXIT_LOCAL
    try:
        update_obj = json.loads(text)
    except json.JSONDecodeError as exc:
        print_error(f"--file is not valid JSON: {exc}")
        return EXIT_LOCAL
    if not isinstance(update_obj, dict):
        print_error("--file must be a JSON object with rule_revisions/activate_at_height")
        return EXIT_LOCAL

    rule_revisions = update_obj.get("rule_revisions")
    activate_at_height = update_obj.get("activate_at_height")
    host_contract_patch = update_obj.get("host_contract_patch")

    try:
        sequence_number = tx_mod.get_sequence(
            sender_pubkey, host=args.host, port=args.port, timeout=args.timeout
        )
    except RuntimeError as exc:
        print_error(str(exc))
        return EXIT_APP_ERROR

    try:
        payload = tx_mod.build_consensus_rule_update_tx(
            sender_pubkey=sender_pubkey,
            sequence_number=sequence_number,
            expiration_time=int(_now()) + args.expiry,
            rule_revisions=rule_revisions or [],
            activate_at_height=activate_at_height or 0,
            host_contract_patch=host_contract_patch,
            fee_limit=args.fee,
        )
    except (ValueError, TypeError) as exc:
        print_error(str(exc))
        return EXIT_LOCAL

    tx_mod.sign_tx(payload, sk_int)
    response = tx_mod.submit_tx(
        payload, host=args.host, port=args.port, timeout=args.timeout
    )

    if args.json:
        print_result(
            {
                "submitted": payload,
                "response": parse_json_response(response),
            },
            json_mode=True,
        )
    else:
        print(response)
    return EXIT_APP_ERROR if rpc_mod.is_error_response(response) else EXIT_OK


def cmd_gov_vote(args: argparse.Namespace) -> int:
    try:
        sk_int, sender_pubkey = _resolve_signing_key(args)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL

    try:
        sequence_number = tx_mod.get_sequence(
            sender_pubkey, host=args.host, port=args.port, timeout=args.timeout
        )
    except RuntimeError as exc:
        print_error(str(exc))
        return EXIT_APP_ERROR

    payload = tx_mod.build_consensus_rule_vote_tx(
        sender_pubkey=sender_pubkey,
        sequence_number=sequence_number,
        expiration_time=int(_now()) + args.expiry,
        update_id=args.update_id,
        approve=True,
        fee_limit=args.fee,
    )
    tx_mod.sign_tx(payload, sk_int)
    response = tx_mod.submit_tx(
        payload, host=args.host, port=args.port, timeout=args.timeout
    )

    if args.json:
        print_result(
            {
                "submitted": payload,
                "response": parse_json_response(response),
            },
            json_mode=True,
        )
    else:
        print(response)
    return EXIT_APP_ERROR if rpc_mod.is_error_response(response) else EXIT_OK


def _now() -> float:
    import time

    return time.time()


# --------------------------------------------------------------------------- #
# Node lifecycle handlers
# --------------------------------------------------------------------------- #


def apply_node_run_env(args: argparse.Namespace, env: dict | None = None) -> dict:
    """Translate `node run` CLI flags into environment variables.

    Mutates ``env`` (defaults to ``os.environ``) and returns it for ergonomics.
    Implicit defaults from ``--test`` use ``setdefault`` so the user's shell
    env wins; explicit flags (``--miner``/``--no-miner``, ``--isolated``/
    ``--no-isolated``, ``--listen``) override unconditionally.

    ``--test`` implies ``--miner --isolated`` unless the user supplies the
    explicit ``--no-miner`` / ``--no-isolated`` opposites.
    """
    import os as _os

    if env is None:
        env = _os.environ

    if args.test:
        env.setdefault("TAU_ENV", "test")
        env.setdefault("TAU_FORCE_TEST", "1")

    miner_explicit = args.miner is not None
    miner = args.miner if miner_explicit else bool(args.test)
    if miner_explicit:
        env["TAU_MINING_ENABLED"] = "true" if miner else "false"
    elif miner:
        env.setdefault("TAU_MINING_ENABLED", "true")

    isolated_explicit = args.isolated is not None
    isolated = args.isolated if isolated_explicit else bool(args.test)
    if isolated:
        if isolated_explicit:
            env["TAU_BOOTSTRAP_PEERS"] = "[]"
        else:
            env.setdefault("TAU_BOOTSTRAP_PEERS", "[]")
    # `isolated == False` (explicit --no-isolated or default without --test):
    # don't touch TAU_BOOTSTRAP_PEERS — let the shell or config default win.

    open_gov_explicit = getattr(args, "open_governance", None) is not None
    open_gov = getattr(args, "open_governance", None)
    if open_gov_explicit:
        if open_gov and not isolated:
            raise ValueError(
                "--open-governance requires an isolated node "
                "(use --isolated or --test without --no-isolated)."
            )
        env["TAU_GOVERNANCE_OPEN_ADMISSION"] = "true" if open_gov else "false"

    if args.fresh:
        env.setdefault("TAU_FORCE_FRESH_START", "1")

    if args.listen:
        env["TAU_NETWORK_LISTEN"] = _normalize_listen_addr(args.listen)

    return env


def _normalize_listen_addr(value: str) -> str:
    """Accept either a libp2p multiaddr or a ``host:port`` IPv4 shorthand.

    Examples::

        /ip4/127.0.0.1/tcp/4001  → unchanged
        127.0.0.1:4001           → /ip4/127.0.0.1/tcp/4001
        0.0.0.0:4001             → /ip4/0.0.0.0/tcp/4001
    """
    v = value.strip()
    if v.startswith("/"):
        return v
    if ":" not in v:
        raise ValueError(
            f"--listen must be a multiaddr or host:port, got {value!r}"
        )
    host, _, port = v.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(
            f"--listen host:port shorthand expects an integer port, got {value!r}"
        )
    return f"/ip4/{host}/tcp/{port}"


def cmd_node_run(args: argparse.Namespace) -> int:
    """Run the node entrypoint in-process.

    The CLI imports ``commands`` / ``config`` before argparse runs, so settings
    are loaded once at startup. Re-apply env from flags here, then reload
    settings so ``--listen``, ``--isolated``, etc. take effect.
    """
    import sys

    import config  # noqa: WPS433 — must reload after apply_node_run_env

    apply_node_run_env(args)
    config.reload_settings()

    sys.argv = ["server"] + (
        ["--ephemeral-identity"] if args.ephemeral_identity else []
    )

    import server  # noqa: E402  (lazy on purpose — see docstring)

    server.main()
    return EXIT_OK


def cmd_node_docker_build(args: argparse.Namespace) -> int:
    try:
        rc = docker_mod.docker_build(
            image=args.image,
            tau_lang_ref=args.tau_lang_ref,
            jobs=args.jobs,
            pull=args.pull,
        )
    except docker_mod.DockerNotFoundError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    return EXIT_OK if rc == 0 else EXIT_APP_ERROR


def cmd_node_docker_run(args: argparse.Namespace) -> int:
    try:
        rc = docker_mod.docker_run(
            image=args.image,
            data_dir=args.data_dir,
            miner=args.miner,
            isolated=args.isolated,
            extra_env=args.env or (),
            detach=args.detach,
            name=args.name,
            no_rm=args.no_rm,
            interactive=args.interactive,
        )
    except (docker_mod.DockerNotFoundError, ValueError) as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    return EXIT_OK if rc == 0 else EXIT_APP_ERROR


def cmd_node_docker_compose_up(args: argparse.Namespace) -> int:
    try:
        rc = docker_mod.docker_compose_up(
            file=args.file,
            build=not args.no_build,
            detach=args.detach,
        )
    except docker_mod.DockerNotFoundError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    return EXIT_OK if rc == 0 else EXIT_APP_ERROR


# --------------------------------------------------------------------------- #
# Argument parser
# --------------------------------------------------------------------------- #


def _build_global_options_parent() -> argparse.ArgumentParser:
    """Parent parser carrying the global flags. Used on every leaf subcommand
    with ``default=argparse.SUPPRESS`` so flags can appear either before or
    after the subcommand without one position clobbering the other.
    """
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--host",
        default=argparse.SUPPRESS,
        help="Node TCP RPC host",
    )
    common.add_argument(
        "--port",
        type=int,
        default=argparse.SUPPRESS,
        help="Node TCP RPC port",
    )
    common.add_argument(
        "--timeout",
        type=float,
        default=argparse.SUPPRESS,
        help="RPC timeout in seconds",
    )
    common.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Emit machine-readable JSON output where possible",
    )
    common.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Verbose logging (includes Python tracebacks on error)",
    )
    return common


_GLOBAL_PARENT = _build_global_options_parent()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tau-testnet",
        description="Tau Testnet developer CLI",
    )
    parser.add_argument(
        "--host",
        default=_default_host(),
        help="Node TCP RPC host (default: %(default)s)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=_default_port(),
        help="Node TCP RPC port (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="RPC timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output where possible",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose logging (includes Python tracebacks on error)",
    )

    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    common = [_GLOBAL_PARENT]

    # version
    p_version = sub.add_parser("version", parents=common, help="Print CLI version")
    p_version.set_defaults(func=cmd_version)

    # ping
    p_ping = sub.add_parser("ping", parents=common, help="TCP handshake with the node")
    p_ping.set_defaults(func=cmd_ping)

    # status
    p_status = sub.add_parser(
        "status",
        parents=common,
        help="Best-effort node status (handshake, timestamp, mempool)",
    )
    p_status.set_defaults(func=cmd_status)

    # rpc
    p_rpc = sub.add_parser(
        "rpc",
        parents=common,
        help="Send a raw command string to the node and print its response",
    )
    p_rpc.add_argument("command", help="Raw command, e.g. 'getbalance <pubkey>'")
    p_rpc.set_defaults(func=cmd_rpc)

    # balance
    p_balance = sub.add_parser("balance", parents=common, help="Query account balance")
    p_balance.add_argument("address", help="Account public key (hex)")
    p_balance.set_defaults(func=cmd_balance)

    # sequence
    p_sequence = sub.add_parser(
        "sequence", parents=common, help="Query next account sequence number"
    )
    p_sequence.add_argument("address", help="Account public key (hex)")
    p_sequence.set_defaults(func=cmd_sequence)

    # history
    p_history = sub.add_parser(
        "history", parents=common, help="Query account transaction history"
    )
    p_history.add_argument("address", help="Account public key (hex)")
    p_history.set_defaults(func=cmd_history)

    # mempool
    p_mempool = sub.add_parser("mempool", parents=common, help="List mempool transactions")
    p_mempool.set_defaults(func=cmd_mempool)

    # blocks
    p_blocks = sub.add_parser("blocks", parents=common, help="List recent blocks")
    p_blocks.add_argument("--limit", type=int, default=None, help="Maximum block count")
    p_blocks.set_defaults(func=cmd_blocks)

    # accounts
    p_accounts = sub.add_parser("accounts", parents=common, help="List all known accounts")
    p_accounts.set_defaults(func=cmd_accounts)

    # tau-state
    p_taustate = sub.add_parser(
        "tau-state", parents=common, help="Get current Tau state formula"
    )
    p_taustate.set_defaults(func=cmd_tau_state)

    # governance
    p_gov = sub.add_parser("governance", parents=common, help="Inspect node governance state")
    p_gov.set_defaults(func=cmd_governance)

    # update-id
    p_update = sub.add_parser(
        "update-id",
        parents=common,
        help="Compute the update-id for a consensus rule update payload",
    )
    update_src = p_update.add_mutually_exclusive_group(required=True)
    update_src.add_argument(
        "--file",
        help="Path to a JSON file with rule_revisions/activate_at_height/host_contract_patch",
    )
    update_src.add_argument(
        "--inline",
        dest="json_payload",
        help="Inline JSON string with the update payload "
        "(use --json for global JSON output mode)",
    )
    p_update.set_defaults(func=cmd_update_id)

    _add_keys_subparsers(sub)
    _add_tx_subparsers(sub)
    _add_gov_subparsers(sub)
    _add_node_subparsers(sub)

    return parser


def _add_node_subparsers(sub) -> None:
    p_node = sub.add_parser("node", help="Node lifecycle and Docker wrappers")
    node_sub = p_node.add_subparsers(
        dest="node_command", required=True, metavar="<command>"
    )

    common = [_GLOBAL_PARENT]

    p_run = node_sub.add_parser(
        "run",
        parents=common,
        help="Run the node in-process (lazy import of server.main)",
    )
    p_run.add_argument(
        "--test",
        action="store_true",
        help="Set TAU_ENV=test and TAU_FORCE_TEST=1, and default --miner / "
        "--isolated to true (override with --no-miner / --no-isolated).",
    )
    p_run.add_argument(
        "--miner",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Toggle TAU_MINING_ENABLED. --no-miner forces it off. "
        "Default: implied true by --test, otherwise defer to env/config.",
    )
    p_run.add_argument(
        "--isolated",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Toggle TAU_BOOTSTRAP_PEERS=[] (no peer bootstrap). "
        "--no-isolated lets the node use the configured bootstrap list. "
        "Default: implied true by --test, otherwise defer to env/config.",
    )
    p_run.add_argument(
        "--open-governance",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Set TAU_GOVERNANCE_OPEN_ADMISSION: any account may submit consensus_rule_update "
        "and consensus_rule_vote (mempool admission). Requires --isolated or implied isolation from --test.",
    )
    p_run.add_argument(
        "--fresh",
        action="store_true",
        help="Set TAU_FORCE_FRESH_START=1 (ignore persisted DB state)",
    )
    p_run.add_argument(
        "--ephemeral-identity",
        action="store_true",
        help="Forward to server.py: use a per-run libp2p identity",
    )
    p_run.add_argument(
        "--listen",
        default=None,
        metavar="ADDR",
        help="Set TAU_NETWORK_LISTEN. Accepts either a multiaddr "
        "(/ip4/127.0.0.1/tcp/4001) or a host:port shorthand (127.0.0.1:4001).",
    )
    p_run.set_defaults(func=cmd_node_run)

    p_build = node_sub.add_parser(
        "docker-build",
        parents=common,
        help="docker build -f Dockerfile.standalone -t <image> .",
    )
    p_build.add_argument(
        "--image",
        default=docker_mod.DEFAULT_IMAGE,
        help="Image tag (default: %(default)s)",
    )
    p_build.add_argument(
        "--tau-lang-ref",
        default=None,
        help="Override the TAU_LANG_REF build arg (git ref of tau-lang)",
    )
    p_build.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="Override the TAU_BUILD_JOBS build arg",
    )
    p_build.add_argument(
        "--pull",
        action="store_true",
        help="Pass --pull to docker build (refresh base image)",
    )
    p_build.set_defaults(func=cmd_node_docker_build)

    p_drun = node_sub.add_parser(
        "docker-run",
        parents=common,
        help="Run the standalone tau-testnet container "
        "(publishes 65432/65433/4001, mounts data dir at /data)",
    )
    p_drun.add_argument("--image", default=docker_mod.DEFAULT_IMAGE)
    p_drun.add_argument(
        "--data-dir",
        default="./data",
        help="Host directory mounted at /data (default: %(default)s)",
    )
    p_drun.add_argument(
        "--miner",
        action="store_true",
        help="Inject -e TAU_MINING_ENABLED=true",
    )
    p_drun.add_argument(
        "--isolated",
        action="store_true",
        help="Inject -e TAU_BOOTSTRAP_PEERS=[] (do not join the public testnet)",
    )
    p_drun.add_argument(
        "--env",
        action="append",
        default=None,
        metavar="KEY=VALUE",
        help="Repeatable extra -e env var",
    )
    p_drun.add_argument("--detach", "-d", action="store_true")
    p_drun.add_argument("--name", default=None)
    p_drun.add_argument(
        "--no-rm",
        action="store_true",
        help="Do not pass --rm (container persists after exit)",
    )
    p_drun.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Pass -it (allocate TTY, attach stdin)",
    )
    p_drun.set_defaults(func=cmd_node_docker_run)

    p_compose = node_sub.add_parser(
        "docker-compose-up",
        parents=common,
        help="docker compose -f docker-compose.standalone.yml up [--build] [-d]",
    )
    p_compose.add_argument(
        "--file",
        default=docker_mod.DEFAULT_COMPOSE_FILE,
        help="Compose file (default: %(default)s)",
    )
    p_compose.add_argument(
        "--no-build",
        action="store_true",
        help="Skip the implicit --build",
    )
    p_compose.add_argument("--detach", "-d", action="store_true")
    p_compose.set_defaults(func=cmd_node_docker_compose_up)


def _add_keys_subparsers(sub) -> None:
    p_keys = sub.add_parser("keys", help="Manage local BLS keypairs")
    keys_sub = p_keys.add_subparsers(
        dest="keys_command", required=True, metavar="<command>"
    )

    common = [_GLOBAL_PARENT]

    p_new = keys_sub.add_parser(
        "new", parents=common, help="Generate a new keypair (printed only)"
    )
    p_new.set_defaults(func=cmd_keys_new)

    p_pub = keys_sub.add_parser(
        "pub", parents=common, help="Derive public key from a private key"
    )
    p_pub.add_argument("--privkey", required=True, help="Private key (hex or decimal)")
    p_pub.set_defaults(func=cmd_keys_pub)

    p_save = keys_sub.add_parser(
        "save",
        parents=common,
        help="Generate a key (or import via --privkey) and save to ~/.tau-testnet/keys",
    )
    p_save.add_argument("--name", required=True, help="Logical key name")
    p_save.add_argument(
        "--privkey",
        default=None,
        help="Optional private key to import (hex or decimal). Without this, "
        "a fresh keypair is generated.",
    )
    p_save.set_defaults(func=cmd_keys_save)

    p_list = keys_sub.add_parser(
        "list", parents=common, help="List saved keys (no private material)"
    )
    p_list.set_defaults(func=cmd_keys_list)

    p_show = keys_sub.add_parser(
        "show", parents=common, help="Show a saved key (public-only by default)"
    )
    p_show.add_argument("name", help="Logical key name")
    p_show.add_argument(
        "--private",
        action="store_true",
        help="Reveal the private key (explicit opt-in)",
    )
    p_show.set_defaults(func=cmd_keys_show)

    p_del = keys_sub.add_parser("delete", parents=common, help="Delete a saved key")
    p_del.add_argument("name", help="Logical key name")
    p_del.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive confirmation; required in non-TTY contexts",
    )
    p_del.set_defaults(func=cmd_keys_delete)


def _add_tx_subparsers(sub) -> None:
    p_tx = sub.add_parser("tx", help="Build, sign, and submit transactions")
    tx_sub = p_tx.add_subparsers(
        dest="tx_command", required=True, metavar="<command>"
    )

    common = [_GLOBAL_PARENT]

    p_send = tx_sub.add_parser(
        "send", parents=common, help="Build, sign, and submit a user transaction"
    )
    src = p_send.add_mutually_exclusive_group(required=True)
    src.add_argument("--key", help="Logical name of a saved key")
    src.add_argument("--privkey", help="Private key (hex or decimal)")
    p_send.add_argument("--to", help="Recipient public key (single transfer)")
    p_send.add_argument(
        "--amount",
        type=int,
        default=None,
        help="Amount for the --to transfer",
    )
    p_send.add_argument(
        "--transfer",
        action="append",
        default=None,
        help="Repeatable 'pubkey:amount' transfer entry",
    )
    p_send.add_argument(
        "--rule-file",
        default=None,
        help="Path to a Tau rule file; its contents go into operations['0']",
    )
    p_send.add_argument(
        "--operations-json",
        default=None,
        help="Path to a JSON file whose object overrides the operations dict",
    )
    p_send.add_argument(
        # Default matches the genesis consensus fee rule (o9); keep in sync
        # with the network's active fee rule.
        "--fee", default="10", help="Fee limit (string-encoded integer; default '10')"
    )
    p_send.add_argument(
        "--expiry",
        type=int,
        default=tx_mod.DEFAULT_EXPIRY_SECONDS,
        help="Seconds until expiration_time (default: %(default)s)",
    )
    p_send.set_defaults(func=cmd_tx_send)

    p_rs = tx_sub.add_parser(
        "raw-sign",
        parents=common,
        help="Sign a JSON payload (no submission); prints the signed JSON",
    )
    p_rs.add_argument("--privkey", required=True, help="Private key (hex or decimal)")
    p_rs.add_argument("--payload", required=True, help="Path to the unsigned JSON payload")
    p_rs.set_defaults(func=cmd_tx_raw_sign)

    p_ru = tx_sub.add_parser(
        "raw-submit", parents=common, help="Submit a pre-signed JSON payload"
    )
    p_ru.add_argument("--file", required=True, help="Path to the signed JSON payload")
    p_ru.set_defaults(func=cmd_tx_raw_submit)


def _add_gov_subparsers(sub) -> None:
    p_gov = sub.add_parser("gov", help="Governance proposals and votes")
    gov_sub = p_gov.add_subparsers(
        dest="gov_command", required=True, metavar="<command>"
    )

    common = [_GLOBAL_PARENT]

    p_list = gov_sub.add_parser(
        "list", parents=common, help="Show governance state (alias for `governance`)"
    )
    p_list.set_defaults(func=cmd_gov_list)

    p_uid = gov_sub.add_parser(
        "update-id", parents=common, help="Compute update-id (alias for `update-id`)"
    )
    uid_src = p_uid.add_mutually_exclusive_group(required=True)
    uid_src.add_argument("--file", help="JSON file with the update payload")
    uid_src.add_argument(
        "--inline",
        dest="json_payload",
        help="Inline JSON string with the update payload",
    )
    p_uid.set_defaults(func=cmd_gov_update_id)

    p_propose = gov_sub.add_parser(
        "propose",
        parents=common,
        help="Build, sign, and submit a consensus_rule_update transaction",
    )
    psrc = p_propose.add_mutually_exclusive_group(required=True)
    psrc.add_argument("--key", help="Logical name of a saved key")
    psrc.add_argument("--privkey", help="Private key (hex or decimal)")
    p_propose.add_argument(
        "--file",
        required=True,
        help="JSON file with rule_revisions / activate_at_height / host_contract_patch",
    )
    p_propose.add_argument("--fee", default="0", help="Fee limit (default '0')")
    p_propose.add_argument(
        "--expiry",
        type=int,
        default=tx_mod.DEFAULT_EXPIRY_SECONDS,
        help="Seconds until expiration_time (default: %(default)s)",
    )
    p_propose.set_defaults(func=cmd_gov_propose)

    p_vote = gov_sub.add_parser(
        "vote",
        parents=common,
        help="Build, sign, and submit a consensus_rule_vote (approve=true)",
    )
    vsrc = p_vote.add_mutually_exclusive_group(required=True)
    vsrc.add_argument("--key", help="Logical name of a saved key")
    vsrc.add_argument("--privkey", help="Private key (hex or decimal)")
    p_vote.add_argument("--update-id", required=True, help="Update id to vote on")
    p_vote.add_argument("--fee", default="0", help="Fee limit (default '0')")
    p_vote.add_argument(
        "--expiry",
        type=int,
        default=tx_mod.DEFAULT_EXPIRY_SECONDS,
        help="Seconds until expiration_time (default: %(default)s)",
    )
    p_vote.set_defaults(func=cmd_gov_vote)


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(getattr(args, "verbose", False))

    handler: Callable[[argparse.Namespace], int] = args.func
    try:
        return handler(args)
    except (rpc_mod.RpcConnectionError, rpc_mod.RpcTimeoutError, rpc_mod.RpcSizeLimitError) as exc:
        print_error(str(exc))
        if args.verbose:
            raise
        return EXIT_NETWORK
    except FileNotFoundError as exc:
        print_error(f"file not found: {exc}")
        if args.verbose:
            raise
        return EXIT_LOCAL
    except (ValueError, KeyError) as exc:
        print_error(str(exc))
        if args.verbose:
            raise
        return EXIT_LOCAL
    except KeyboardInterrupt:
        print_error("interrupted")
        return EXIT_LOCAL


if __name__ == "__main__":
    raise SystemExit(main())
