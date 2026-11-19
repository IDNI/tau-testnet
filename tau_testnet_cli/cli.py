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
    return _simple_query_response(args, _send(args, command))


def _simple_query_response(args: argparse.Namespace, response: str) -> int:
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


FEE_HELP = (
    "Fee limit (string-encoded integer). Default: the node's fee estimate "
    "from 'checktx estimate'"
)


def _sign_with_fee(args: argparse.Namespace, payload: dict, sk_int) -> dict:
    """Sign with --fee, or with the node's fee estimate when --fee is absent.

    The estimate does not depend on fee_limit, so a draft signed with 0 gets
    the fee of the final transaction. A command with no --fee keeps its 0.
    """
    fee = getattr(args, "fee", None)
    if fee is None and hasattr(args, "fee"):
        payload["fee_limit"] = "0"
        tx_mod.sign_tx(payload, sk_int)
        fee = tx_mod.estimate_fee(
            payload, host=args.host, port=args.port, timeout=args.timeout
        )
    if fee is not None:
        payload["fee_limit"] = str(fee)
    return tx_mod.sign_tx(payload, sk_int)


def _no_fee_estimate(exc: RuntimeError) -> int:
    print_error(
        f"the node gave no fee estimate ({exc}); give the fee limit with --fee"
    )
    return EXIT_APP_ERROR


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
        sequence_number, tip = tx_mod.get_sequence_and_tip(
            sender_pubkey,
            host=args.host,
            port=args.port,
            timeout=args.timeout,
        )
    except RuntimeError as exc:
        print_error(str(exc))
        return EXIT_APP_ERROR

    payload = tx_mod.build_user_tx(
        sender_pubkey=sender_pubkey,
        sequence_number=sequence_number,
        expiration_time=int(_now()) + int(args.expiry),
        expire_at_height=_resolve_expire_at_height(args, tip=tip),
        operations=operations,
    )
    try:
        _sign_with_fee(args, payload, sk_int)
    except RuntimeError as exc:
        return _no_fee_estimate(exc)

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
        sequence_number, tip = tx_mod.get_sequence_and_tip(
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
            expire_at_height=_resolve_expire_at_height(args, tip=tip),
            rule_revisions=rule_revisions or [],
            activate_at_height=activate_at_height or 0,
            host_contract_patch=host_contract_patch,
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
        sequence_number, tip = tx_mod.get_sequence_and_tip(
            sender_pubkey, host=args.host, port=args.port, timeout=args.timeout
        )
    except RuntimeError as exc:
        print_error(str(exc))
        return EXIT_APP_ERROR

    payload = tx_mod.build_consensus_rule_vote_tx(
        sender_pubkey=sender_pubkey,
        sequence_number=sequence_number,
        expiration_time=int(_now()) + args.expiry,
        expire_at_height=_resolve_expire_at_height(args, tip=tip),
        update_id=args.update_id,
        approve=True,
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


# --------------------------------------------------------------------------- #
# Rule sharing handlers
# --------------------------------------------------------------------------- #


def _read_rule_text(args: argparse.Namespace) -> str:
    """Rule text from --rule or --rule-file.

    Read verbatim: an accept must repeat the offered text byte-for-byte because
    the node recomputes the offer id from it, so no reformatting happens here.
    """
    if getattr(args, "rule", None):
        return args.rule
    path = getattr(args, "rule_file", None)
    if not path:
        raise _PayloadError("one of --rule or --rule-file is required")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise _PayloadError(f"cannot read {path}: {exc}") from exc


def _submit_rule_tx(args: argparse.Namespace, build, *, pass_tip: bool = False) -> int:
    """Shared build -> sign -> submit path for the three rule-sharing types.

    `build` is called with (pubkey, sequence, expire_at_height): the height is
    resolved once here, from the tip that came back with the sequence, so no
    builder has to ask for it again. `pass_tip` appends that tip as a fourth
    argument for builders that count a release point from it.
    """
    try:
        sk_int, sender_pubkey = _resolve_signing_key(args)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL

    try:
        sequence_number, tip = tx_mod.get_sequence_and_tip(
            sender_pubkey, host=args.host, port=args.port, timeout=args.timeout
        )
    except RuntimeError as exc:
        print_error(str(exc))
        return EXIT_APP_ERROR

    try:
        height = _resolve_expire_at_height(args, tip=tip)
        payload = (build(sender_pubkey, sequence_number, height, tip) if pass_tip
                   else build(sender_pubkey, sequence_number, height))
    except (_PayloadError, ValueError) as exc:
        print_error(str(exc))
        return EXIT_LOCAL

    try:
        _sign_with_fee(args, payload, sk_int)
    except RuntimeError as exc:
        return _no_fee_estimate(exc)
    if getattr(args, "dry_run", False):
        print_result(payload, json_mode=True)
        return EXIT_OK
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


def cmd_rule_offer(args: argparse.Namespace) -> int:
    try:
        rule_text = _read_rule_text(args)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL

    return _submit_rule_tx(
        args,
        lambda pubkey, seq, height: tx_mod.build_rule_offer_tx(
            sender_pubkey=pubkey,
            sequence_number=seq,
            expiration_time=int(_now()) + args.expiry,
            recipient_pubkey=args.to,
            rule_text=rule_text,
            expire_at_height=height,
        ),
    )


def cmd_rule_list(args: argparse.Namespace) -> int:
    address = args.address
    if not address:
        try:
            _sk, address = _resolve_signing_key(args)
        except _PayloadError as exc:
            print_error(str(exc))
            return EXIT_LOCAL
    role = getattr(args, "role", "all")
    return _simple_query(args, f"getruleoffers {address} {role}")


def cmd_rule_show(args: argparse.Namespace) -> int:
    return _simple_query(args, f"getruleoffer {args.offer_id}")


def cmd_rule_check(args: argparse.Namespace) -> int:
    return _simple_query(args, f"getruleconflict {args.offer_id}")


def cmd_rule_accept(args: argparse.Namespace) -> int:
    """Accept an offer, after showing its conflict report.

    The rule text is fetched from the node rather than retyped, so the accept
    carries the offered bytes exactly; the node recomputes the offer digest from
    them and refuses anything that does not match.
    """
    detail_raw = _send(args, f"getruleoffer {args.offer_id}")
    if rpc_mod.is_error_response(detail_raw):
        print(detail_raw)
        return EXIT_APP_ERROR
    try:
        offer = parse_json_response(detail_raw)["data"]
        rule_text = offer["rule_text"]
    except Exception:
        print_error("node returned an unreadable offer")
        return EXIT_APP_ERROR
    if not rule_text:
        print_error(
            "this node no longer has the offer text (it is node-local); accept "
            "from a node that does, or pass --rule-file with the exact bytes"
        )
        return EXIT_APP_ERROR

    if getattr(args, "rule_file", None):
        try:
            rule_text = _read_rule_text(args)
        except _PayloadError as exc:
            print_error(str(exc))
            return EXIT_LOCAL

    verdict = None
    conflict_raw = _send(args, f"getruleconflict {args.offer_id}")
    if not rpc_mod.is_error_response(conflict_raw):
        try:
            report = parse_json_response(conflict_raw)["data"]
            verdict = report.get("verdict")
            if not args.json:
                print(f"conflict check: {verdict}")
                for layer in report.get("layers", []):
                    line = f"  {layer['layer']}: {layer['status']}"
                    if layer.get("detail"):
                        line += f" -- {layer['detail']}"
                    print(line)
        except Exception:
            verdict = None

    if verdict in ("warn", "conflict") and not args.yes:
        print_error(
            f"conflict check returned '{verdict}'; re-run with --yes to accept anyway"
        )
        return EXIT_APP_ERROR

    return _submit_rule_tx(
        args,
        lambda pubkey, seq, height: tx_mod.build_rule_offer_accept_tx(
            sender_pubkey=pubkey,
            sequence_number=seq,
            expiration_time=int(_now()) + args.expiry,
            expire_at_height=height,
            offer_id=args.offer_id,
            rule_text=rule_text,
        ),
    )


def cmd_rule_reject(args: argparse.Namespace) -> int:
    return _submit_rule_tx(
        args,
        lambda pubkey, seq, height: tx_mod.build_rule_offer_reject_tx(
            sender_pubkey=pubkey,
            sequence_number=seq,
            expiration_time=int(_now()) + args.expiry,
            expire_at_height=height,
            offer_id=args.offer_id,
        ),
    )


def cmd_rule_offer_id(args: argparse.Namespace) -> int:
    import json as _json

    try:
        rule_text = _read_rule_text(args)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    payload = {
        "sender_pubkey": args.from_pubkey,
        "recipient_pubkey": args.to,
        "rule_text": rule_text,
        "expire_at_height": args.expire_at_height,
    }
    blob = _json.dumps(payload, separators=(",", ":"))
    return _simple_query(args, f"getofferid '{blob}'")


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
    _add_rule_subparsers(sub)
    _add_approval_subparsers(sub)
    _add_policy_subparsers(sub)
    _add_retractable_subparsers(sub)
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
    p_send.add_argument("--fee", default=None, help=FEE_HELP)
    p_send.add_argument(
        "--expiry",
        type=int,
        default=tx_mod.DEFAULT_EXPIRY_SECONDS,
        help="Seconds until expiration_time (default: %(default)s)",
    )
    # The deadline that actually binds: expiration_time is rechecked against the
    # block timestamp, which the proposer picks, while a height cannot be moved.
    p_send.add_argument(
        "--expire-in",
        type=_block_count,
        default=tx_mod.DEFAULT_EXPIRY_BLOCKS,
        help="Blocks the transaction may land in, from the next one (default: %(default)s)",
    )
    p_send.add_argument(
        "--expire-at-height",
        type=int,
        default=None,
        help="Absolute expiry height (overrides --expire-in)",
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



# --- Co-signature approvals -------------------------------------------------


def _parse_kv_pairs(values, what, sep="="):
    """`--approver 18=<pubkey>` / `--input 26=text` -> {18: "<pubkey>"}."""
    out = {}
    for raw in values or []:
        if sep not in raw:
            raise _PayloadError(f"--{what} expects <stream>{sep}<value>, got {raw!r}")
        key, _, value = raw.partition(sep)
        try:
            idx = int(key.strip())
        except ValueError:
            raise _PayloadError(f"--{what}: {key!r} is not a stream index")
        if idx in out:
            raise _PayloadError(f"--{what}: stream {idx} given twice")
        out[idx] = value
    return out


def _tip_height(args) -> int:
    """The node's tip, from getblocks. Last resort: `getsequence` carries it.

    Asks for the most recent block only: a bare `getblocks` returns the whole
    chain, which on a long one outgrows the 4 MiB read ceiling. A node old
    enough to ignore the limit answers with every block, and the max below
    still finds the tip.
    """
    response = rpc_mod.send_command(
        "getblocks 1", host=args.host, port=args.port, timeout=args.timeout
    )
    parsed = parse_json_response(response)
    blocks = ((parsed or {}).get("data") or {}).get("blocks") or []
    tip = 0
    for block in blocks:
        try:
            tip = max(tip, int(block["header"]["block_number"]))
        except (KeyError, TypeError, ValueError):
            continue
    return tip


def _block_count(text: str) -> int:
    """argparse type for --expire-in: 0 would build a transaction that is
    expired before it is sent."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid int value: {text!r}")
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {value}")
    return value


def _resolve_expire_at_height(args, *, tip: int | None = None) -> int:
    """--expire-at-height wins; otherwise next height + --expire-in.

    Admission refuses `expire_at_height <= tip + 1` and a block at height H
    takes a transaction only while H < expire_at_height, so counting from the
    next height makes --expire-in the number of blocks the transaction can land
    in: `--expire-in 1` means "the next block or never", never "already dead".

    A `tip` of 0 is not trusted: a node too old to report `tip_height` with the
    sequence answers 0, and measuring the deadline from there on a chain at
    height 5,000 builds a transaction that is already dead. Asking getblocks
    costs one extra round trip on a genuinely empty chain, which is the cheap
    side of that trade.
    """
    explicit = getattr(args, "expire_at_height", None)
    if explicit is not None:
        return int(explicit)
    expire_in = getattr(args, "expire_in", None)
    expire_in = tx_mod.DEFAULT_EXPIRY_BLOCKS if expire_in is None else int(expire_in)
    if expire_in < 1:
        raise ValueError(f"--expire-in must be at least 1, got {expire_in}")
    if not tip:
        tip = _tip_height(args)
    return tip + 1 + expire_in


def _auto_discover_approvers(args, sender_pubkey, amount, recipient) -> dict:
    """Ask the node which approvers this amount actually needs.

    Advisory, and that is the point: the wallet that wrote the policy knows the
    answer, but a fresh CLI does not, and guessing means over-declaring -- which
    notifies people whose signature the policy never asks for.
    """
    slots_resp = rpc_mod.send_command(
        f"getapprovalslots {sender_pubkey}",
        host=args.host, port=args.port, timeout=args.timeout,
    )
    slots_data = ((parse_json_response(slots_resp) or {}).get("data") or {})
    candidates = slots_data.get("slots") or {}
    if not candidates:
        raise _PayloadError(
            "Could not read your policy clause, so --auto has nothing to work "
            "from. Declare approvers explicitly with --approver <slot>=<pubkey>."
        )

    draft = json.dumps({
        "sender_pubkey": sender_pubkey,
        "recipient_pubkey": recipient,
        "amount": amount,
        "approvers": candidates,
    })
    preview = rpc_mod.send_command(
        f"getapprovalpreview {draft}",
        host=args.host, port=args.port, timeout=args.timeout,
    )
    data = ((parse_json_response(preview) or {}).get("data") or {})
    if not data.get("available", False):
        raise _PayloadError(
            "Node could not determine the required approvers "
            f"({data.get('reason', 'unavailable')}). Declare them explicitly."
        )
    if data.get("needs_no_approval"):
        raise _PayloadError(
            "Your policy allows this transfer with no votes, so it needs no "
            "approval request -- send it with `tx send`."
        )
    if not data.get("satisfiable", False):
        raise _PayloadError(
            "Your own policy would never allow this transfer, whoever signs. "
            "Nothing would be gained by parking it."
        )
    required = data.get("required_approvers") or {}
    if not required:
        raise _PayloadError("Node returned no required approvers.")
    return {int(k): v for k, v in required.items()}


def cmd_approval_request(args: argparse.Namespace) -> int:
    explicit = None
    try:
        explicit = _parse_kv_pairs(getattr(args, "approver", None), "approver")
        customs = _parse_kv_pairs(getattr(args, "input", None), "input")
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL

    if customs and not args.yes:
        # Anything in a custom input is on-chain and public forever. A TOTP code
        # there is readable by everyone for its whole validity window, which is
        # why the bot also accepts codes over its own endpoint.
        print_error(
            "Custom inputs are PUBLIC and permanent on chain. A one-time code "
            "placed here is readable by anyone for its validity window -- prefer "
            "sending it to the bot's own endpoint. Re-run with --yes to confirm."
        )
        return EXIT_LOCAL

    def _build(sender_pubkey, sequence_number, expire_at_height):
        approvers = explicit
        if not approvers:
            if not getattr(args, "auto", False):
                raise _PayloadError(
                    "Declare approvers with --approver <slot>=<pubkey>, or pass "
                    "--auto to ask the node which ones this amount needs."
                )
            approvers = _auto_discover_approvers(
                args, sender_pubkey, int(args.amount), args.to.lower()
            )
        return tx_mod.build_approval_request_tx(
            sender_pubkey=sender_pubkey,
            sequence_number=sequence_number,
            expiration_time=int(_now()) + args.expiry,
            recipient_pubkey=args.to,
            amount=int(args.amount),
            expire_at_height=expire_at_height,
            approvers=approvers,
            custom_inputs=customs,
        )

    return _submit_rule_tx(args, _build)


def cmd_approval_vote(args: argparse.Namespace, approve: bool) -> int:
    def _build(sender_pubkey, sequence_number, expire_at_height):
        return tx_mod.build_transfer_vote_tx(
            sender_pubkey=sender_pubkey,
            sequence_number=sequence_number,
            expiration_time=int(_now()) + args.expiry,
            expire_at_height=expire_at_height,
            request_id=args.request_id,
            approve=approve,
            reason=getattr(args, "reason", "") or "",
        )

    if approve and getattr(args, "code", None):
        # The code never goes on chain: six digits is brute-forceable from any
        # on-chain form. It goes to the bot, which verifies it and then signs its
        # own vote -- so this CLI has nothing to submit.
        print_error(
            "A --code is verified by the auth bot, not by the chain. Send it to "
            "the bot's endpoint (scripts/approval_bot_totp.py --help); it will "
            "cast its own vote."
        )
        return EXIT_LOCAL
    return _submit_rule_tx(args, _build)


def _address_or_key(args):
    """Explicit address, else the address of the signing key."""
    if getattr(args, "address", None):
        return args.address
    _sk, address = _resolve_signing_key(args)
    return address


def cmd_approval_list(args: argparse.Namespace) -> int:
    try:
        address = _address_or_key(args)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    role = getattr(args, "role", "all")
    return _approval_query(args, f"getapprovalrequests {address} {role}")


def cmd_approval_show(args: argparse.Namespace) -> int:
    return _approval_query(args, f"getapprovalrequest {args.request_id}")


BODY_INLINE_LIMIT = 500


def _is_rule_change_row(row) -> bool:
    return isinstance(row, dict) and row.get("request_type") == "rule_change"


def render_rule_change_row(row: dict, indent: str = "") -> list[str]:
    """Readable lines for one rule-change request row."""
    lines = [
        f"{indent}rule change {row.get('request_id', '?')}",
        f"{indent}  kind: {row.get('kind_name', '?')} ({row.get('kind', '?')})",
        f"{indent}  requester: {row.get('sender_pubkey') or row.get('sender', '?')}",
        f"{indent}  status: {row.get('status', '?')}"
        + (" (ready to release)" if row.get("ready") else ""),
    ]
    body = row.get("body") or ""
    if row.get("offer_id"):
        lines.append(f"{indent}  offer: {row['offer_id']}")
    if body and len(body) <= BODY_INLINE_LIMIT:
        lines.append(f"{indent}  body: {body}")
    elif body:
        lines.append(
            f"{indent}  body: {len(body)} chars, hash {row.get('body_hash', '?')}"
        )
    lines.append(
        f"{indent}  created at height {row.get('created_height', '?')}, "
        f"time escape at height {row.get('escape_height', '?')}, "
        f"expires at height {row.get('expire_at_height', '?')}"
    )
    approvers = row.get("approvers") or {}
    if approvers:
        lines.append(f"{indent}  approvers:")
        for slot, info in approvers.items():
            if isinstance(info, dict):
                lines.append(
                    f"{indent}    i{slot}: {info.get('pubkey', '?')} "
                    f"[{info.get('state', '?')}]"
                )
            else:
                lines.append(f"{indent}    i{slot}: {info}")
    else:
        lines.append(f"{indent}  approvers: none (releases at the time escape)")
    return lines


def _approval_query(args: argparse.Namespace, command: str) -> int:
    """_simple_query, but rule-change rows print as readable text."""
    response = _send(args, command)
    if rpc_mod.is_error_response(response) or args.json:
        return _simple_query_response(args, response)
    parsed = parse_json_response(response)
    data = (parsed or {}).get("data") if isinstance(parsed, dict) else None
    if not isinstance(data, dict):
        return _simple_query_response(args, response)

    if _is_rule_change_row(data):
        extra = {k: data[k] for k in ("awaiting_slots", "all_answered") if k in data}
        print("\n".join(render_rule_change_row(data)))
        if extra:
            print(f"  awaiting slots: {extra.get('awaiting_slots')}, "
                  f"all answered: {extra.get('all_answered')}")
        return EXIT_OK

    sections = [k for k in ("incoming", "outgoing") if isinstance(data.get(k), list)]
    if not any(_is_rule_change_row(r) for k in sections for r in data[k]):
        return _simple_query_response(args, response)
    for key in sections:
        print(f"{key}: {len(data[key])}")
        for row in data[key]:
            if _is_rule_change_row(row):
                print("\n".join(render_rule_change_row(row, "  ")))
            else:
                print(json.dumps(row, indent=2, default=str))
    return EXIT_OK


def cmd_approval_slots(args: argparse.Namespace) -> int:
    try:
        address = _address_or_key(args)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    return _simple_query(args, f"getapprovalslots {address}")


def cmd_approval_preview(args: argparse.Namespace) -> int:
    try:
        address = _address_or_key(args)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    slots_resp = rpc_mod.send_command(
        f"getapprovalslots {address}",
        host=args.host, port=args.port, timeout=args.timeout,
    )
    candidates = (((parse_json_response(slots_resp) or {}).get("data") or {})
                  .get("slots") or {})
    draft = json.dumps({
        "sender_pubkey": address,
        "recipient_pubkey": args.to,
        "amount": int(args.amount),
        "approvers": candidates,
    })
    return _simple_query(args, f"getapprovalpreview {draft}")


def cmd_approval_request_id(args: argparse.Namespace) -> int:
    payload = json.dumps({
        "sender_pubkey": args.from_pubkey,
        "recipient_pubkey": args.to,
        "amount": int(args.amount),
        "sequence_number": int(args.sequence),
        "expire_at_height": int(args.expire_at_height),
        "approvers": _parse_kv_pairs(getattr(args, "approver", None), "approver"),
    })
    return _simple_query(args, f"getrequestid {payload}")


def _add_approval_subparsers(sub) -> None:
    """`tau-testnet approval ...` -- park a transfer, vote on one, inspect them.

    The inbox commands are the ones an approver bot polls; `request --auto` is
    for a client that does not know which approvers an amount needs and would
    otherwise over-declare, notifying people the policy never asks for.
    """
    p_appr = sub.add_parser(
        "approval",
        parents=[_GLOBAL_PARENT],
        help="Co-signature approvals (park a transfer, vote, inspect)",
    )
    asub = p_appr.add_subparsers(dest="approval_command", required=True)
    common = [_GLOBAL_PARENT]

    def _key_group(parser, required=True):
        src = parser.add_mutually_exclusive_group(required=required)
        src.add_argument("--key", help="Logical name of a saved key")
        src.add_argument("--privkey", help="Private key (hex or decimal)")

    def _tx_flags(parser, fee=True):
        if fee:
            parser.add_argument("--fee", default=None, help=FEE_HELP)
        parser.add_argument(
            "--expiry", type=int, default=tx_mod.DEFAULT_EXPIRY_SECONDS,
            help="Seconds until expiration_time (default: %(default)s)",
        )

    # --- request ---
    p_req = asub.add_parser(
        "request", parents=common,
        help="Park a transfer that needs co-signatures",
    )
    _key_group(p_req)
    p_req.add_argument("--to", required=True, help="Recipient public key (96 hex)")
    p_req.add_argument("--amount", required=True, type=int, help="Amount to transfer")
    p_req.add_argument(
        "--approver", action="append", metavar="SLOT=PUBKEY",
        help=(
            "Approver for one slot, e.g. --approver 18=<pubkey>. Declare ONLY "
            "the approvers this amount needs: the declaration is what fills "
            "inboxes. Repeatable."
        ),
    )
    p_req.add_argument(
        "--auto", action="store_true",
        help="Ask the node which approvers this amount requires (advisory).",
    )
    p_req.add_argument(
        "--input", action="append", metavar="STREAM=VALUE",
        help=(
            "Sender data an approver can read, stream >= 26, e.g. "
            "--input 26='rent for Q3'. PUBLIC and permanent. Repeatable."
        ),
    )
    p_req.add_argument("--expire-in", type=_block_count, default=1000,
                       help="Blocks the request may land in, from the next one")
    p_req.add_argument("--expire-at-height", type=int,
                       help="Absolute expiry height (overrides --expire-in)")
    p_req.add_argument("--yes", action="store_true",
                       help="Confirm putting data in a PUBLIC custom input")
    _tx_flags(p_req)
    p_req.set_defaults(func=cmd_approval_request)

    # --- approve / decline ---
    p_ok = asub.add_parser("approve", parents=common,
                           help="Approve a parked transfer")
    _key_group(p_ok)
    p_ok.add_argument("request_id", help="Request id (64 hex)")
    p_ok.add_argument("--code", help="TOTP code -- goes to the BOT, never on chain")
    # Votes are fee-exempt: an approver needs no funds and no fee strategy.
    _tx_flags(p_ok, fee=False)
    p_ok.set_defaults(func=lambda a: cmd_approval_vote(a, approve=True))

    p_no = asub.add_parser(
        "decline", parents=common,
        help="Decline to sign (does NOT cancel the request)",
    )
    _key_group(p_no)
    p_no.add_argument("request_id", help="Request id (64 hex)")
    p_no.add_argument("--reason", default="", help="Note for the sender (<=256 bytes)")
    _tx_flags(p_no, fee=False)
    p_no.set_defaults(func=lambda a: cmd_approval_vote(a, approve=False))

    # --- reads ---
    p_list = asub.add_parser("list", parents=common,
                             help="Requests involving an address (the inbox)")
    p_list.add_argument("address", nargs="?", help="Address (default: your key's)")
    _key_group(p_list, required=False)
    p_list.add_argument("--role", choices=["in", "out", "all"], default="all")
    p_list.set_defaults(func=cmd_approval_list)

    p_show = asub.add_parser("show", parents=common, help="One request in full")
    p_show.add_argument("request_id", help="Request id (64 hex)")
    p_show.set_defaults(func=cmd_approval_show)

    p_slots = asub.add_parser(
        "slots", parents=common,
        help="Which approver sits in which slot of a policy (advisory)",
    )
    p_slots.add_argument("address", nargs="?", help="Address (default: your key's)")
    _key_group(p_slots, required=False)
    p_slots.set_defaults(func=cmd_approval_slots)

    p_prev = asub.add_parser(
        "preview", parents=common,
        help="Which approvers would this transfer need? (advisory)",
    )
    p_prev.add_argument("address", nargs="?", help="Address (default: your key's)")
    _key_group(p_prev, required=False)
    p_prev.add_argument("--to", required=True, help="Recipient public key (96 hex)")
    p_prev.add_argument("--amount", required=True, type=int, help="Amount")
    p_prev.set_defaults(func=cmd_approval_preview)

    p_rid = asub.add_parser("request-id", parents=common,
                            help="Derive a request id without submitting")
    p_rid.add_argument("--from-pubkey", required=True, help="Sender public key")
    p_rid.add_argument("--to", required=True, help="Recipient public key")
    p_rid.add_argument("--amount", required=True, type=int)
    p_rid.add_argument("--sequence", required=True, type=int)
    p_rid.add_argument("--expire-at-height", required=True, type=int)
    p_rid.add_argument("--approver", action="append", metavar="SLOT=PUBKEY")
    p_rid.set_defaults(func=cmd_approval_request_id)


# --- Policy guard and rule-change requests ---------------------------------


_KIND_BY_NAME = {"set": 1, "revoke": 2, "accept": 3}
_KIND_GUARD_SET = 4
_KIND_GUARD_REVOKE = 5


def _read_policy_body(args: argparse.Namespace) -> str:
    if getattr(args, "body", None):
        return args.body
    path = getattr(args, "file", None)
    if not path:
        raise _PayloadError("one of --file or --body is required")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        raise _PayloadError(f"cannot read {path}: {exc}") from exc


def _fetch_offer_text(args: argparse.Namespace, offer_id: str) -> str:
    raw = _send(args, f"getruleoffer {offer_id}")
    if rpc_mod.is_error_response(raw):
        raise _PayloadError(f"cannot read offer {offer_id}: {raw}")
    try:
        text = parse_json_response(raw)["data"]["rule_text"]
    except Exception:
        raise _PayloadError("node returned an unreadable offer")
    if not text:
        raise _PayloadError(
            "this node no longer has the offer text (it is node-local); ask a "
            "node that does"
        )
    return text


def _print_rule_change_preview(data: dict) -> None:
    print(f"kind: {data.get('kind_name', '?')}")
    print(f"guard on this account: {'yes' if data.get('has_guard') else 'no'}")
    screen = data.get("screen") or {}
    if screen and not screen.get("ok", True):
        print(f"screen: REFUSED -- {screen.get('error')}")
    elif screen:
        print("screen: ok")
    if not data.get("available", True):
        print(f"preview unavailable: {data.get('reason', 'unknown reason')}")
        return
    if data.get("executes_immediately"):
        print("result: executes in the block that carries the request")
    elif data.get("satisfiable"):
        required = data.get("required_approvers") or {}
        print("result: parks until approvers vote; fewest approvers needed:")
        for slot, key in required.items():
            print(f"  i{slot}: {key}")
        extra = len(data.get("allowing_subsets") or []) - 1
        if extra > 0:
            print(f"  ({extra} other approving combination(s) also work)")
    else:
        print("result: no declared approvers would let the guard allow this")
    delay = data.get("escape_delay_blocks")
    if delay is not None:
        print(f"time escape: releases {delay} blocks after the request is mined")


def _preview_rule_change(args, sender, kind, rule_text, offer_id, approvers) -> int:
    draft = {
        "request_type": "rule_change",
        "sender_pubkey": sender,
        "kind": kind,
        "rule_text": rule_text,
        "offer_id": offer_id,
        "approvers": {str(k): v for k, v in approvers.items()},
    }
    raw = _send(args, f"getapprovalpreview {json.dumps(draft)}")
    if rpc_mod.is_error_response(raw):
        if args.json:
            print_result({"error": raw}, json_mode=True)
        else:
            print(raw)
        return EXIT_APP_ERROR
    if args.json:
        print_result(parse_json_response(raw), json_mode=True)
        return EXIT_OK
    data = (parse_json_response(raw) or {}).get("data") or {}
    _print_rule_change_preview(data)
    return EXIT_OK


def _submit_rule_change(
    args: argparse.Namespace, kind: int, rule_text: str, offer_id: str
) -> int:
    import tau_defs
    from consensus.approvals import (
        MAX_APPROVAL_WINDOW_BLOCKS,
        parse_rule_change_request_checked,
    )

    try:
        approvers = _parse_kv_pairs(getattr(args, "approver", None), "approver")
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL

    if getattr(args, "preview", False):
        try:
            _sk, sender = _resolve_signing_key(args)
        except _PayloadError as exc:
            print_error(str(exc))
            return EXIT_LOCAL
        return _preview_rule_change(args, sender, kind, rule_text, offer_id, approvers)

    created = {}

    def _build(sender_pubkey, sequence_number, expire_at_height, tip):
        window = expire_at_height - (tip + 1)
        if window > MAX_APPROVAL_WINDOW_BLOCKS:
            raise _PayloadError(
                f"the expiry is {window} blocks ahead; the most a request may "
                f"ask for is {MAX_APPROVAL_WINDOW_BLOCKS}"
            )
        if window <= tau_defs.RULE_CHANGE_DELAY_BLOCKS:
            print(
                f"warning: this request expires {window} blocks from the next "
                f"block, before the {tau_defs.RULE_CHANGE_DELAY_BLOCKS}-block "
                "time escape, so it can only release through approvals.",
                file=sys.stderr,
            )
        payload = tx_mod.build_rule_change_request_tx(
            sender_pubkey=sender_pubkey,
            sequence_number=sequence_number,
            expiration_time=int(_now()) + args.expiry,
            expire_at_height=expire_at_height,
            kind=kind,
            rule_text=rule_text,
            offer_id=offer_id,
            approvers=approvers,
        )
        request, why = parse_rule_change_request_checked(payload)
        if request is None:
            raise _PayloadError(why)
        created["id"] = request.request_id.hex()
        return payload

    status = _submit_rule_tx(args, _build, pass_tip=True)
    if status == EXIT_OK and created.get("id"):
        quiet = args.json or getattr(args, "dry_run", False)
        print(f"request id: {created['id']}", file=sys.stderr if quiet else sys.stdout)
    return status


def cmd_policy_guard_set(args: argparse.Namespace) -> int:
    try:
        body = _read_policy_body(args)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    return _submit_rule_change(args, _KIND_GUARD_SET, body, "")


def cmd_policy_guard_revoke(args: argparse.Namespace) -> int:
    return _submit_rule_change(args, _KIND_GUARD_REVOKE, "", "")


def cmd_policy_guard_show(args: argparse.Namespace) -> int:
    try:
        address = _address_or_key(args)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    raw = _send(args, f"getruleoffers {address} all")
    if rpc_mod.is_error_response(raw):
        if args.json:
            print_result({"error": raw}, json_mode=True)
        else:
            print(raw)
        return EXIT_APP_ERROR
    data = (parse_json_response(raw) or {}).get("data") or {}
    guard = data.get("rule_change_guard")
    if args.json:
        print_result({"address": address, "rule_change_guard": guard}, json_mode=True)
    elif guard:
        print(f"guard for {address}:\n{guard}")
    else:
        print(f"no rule-change guard on {address}")
    return EXIT_OK


def cmd_policy_change_request(args: argparse.Namespace) -> int:
    kind = _KIND_BY_NAME[args.kind]
    rule_text, offer_id = "", ""
    try:
        if kind == 1:
            rule_text = _read_policy_body(args)
        elif kind == 3:
            if not args.offer_id:
                raise _PayloadError("--kind accept needs --offer-id")
            offer_id = args.offer_id.strip().lower()
            rule_text = _fetch_offer_text(args, offer_id)
        elif getattr(args, "body", None) or getattr(args, "file", None) \
                or getattr(args, "offer_id", None):
            raise _PayloadError("--kind revoke carries no body or offer id")
        if kind != 3 and getattr(args, "offer_id", None):
            raise _PayloadError("--offer-id only applies to --kind accept")
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    return _submit_rule_change(args, kind, rule_text, offer_id)


def cmd_policy_change_cancel(args: argparse.Namespace) -> int:
    def _build(sender_pubkey, sequence_number, expire_at_height):
        return tx_mod.build_rule_change_cancel_tx(
            sender_pubkey=sender_pubkey,
            sequence_number=sequence_number,
            expiration_time=int(_now()) + args.expiry,
            expire_at_height=expire_at_height,
            request_id=args.request_id,
        )

    return _submit_rule_tx(args, _build)


# --- Recipient controls: inbound policy composition -------------------------
# Pure text composition for the recipient-side o5 gate (issues #47, #76). These
# helpers print the exact `always ( ... ).` unit plus the command to register it
# through the existing sendtx / rule-change flow; they touch no node and sign
# nothing, so they work on a build where the consensus feature has not landed.


def _receive_stream_indices() -> tuple:
    """Hold stream indices, preferring the tau_defs constants the consensus
    feature defines. Literal 17/27 until they land, so composition works on any
    build (the frozen contract: i17 = hold seconds, i27 = hold blocks)."""
    import tau_defs

    return (
        getattr(tau_defs, "HOLD_SECONDS_STREAM_INDEX", 17),
        getattr(tau_defs, "HOLD_BLOCKS_STREAM_INDEX", 27),
    )


def _receive_pubkey(text: str) -> str:
    """Normalize a pubkey argument (optional 0x prefix) to 96 lowercase hex."""
    raw = (text or "").strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if len(raw) != 96 or any(c not in "0123456789abcdef" for c in raw):
        raise _PayloadError(f"{text!r} is not a 96-character hex public key")
    return raw


def _receive_pubkey_literal(stream: str, pubkey: str) -> str:
    return f"({stream}[t]:bv[384] = {{ #x{pubkey} }}:bv[384])"


def _receive_hold_literal(index: int, value: int) -> str:
    # Canonical comparison the gate reads to report the cap in a refusal.
    return f"i{index}[t]:bv[64] <= {{ {value} }}:bv[64]"


def _receive_cap(value, label: str):
    if value is None:
        return None
    if not isinstance(value, int) or value < 0 or value >= (1 << 64):
        raise _PayloadError(f"{label} must be an integer between 0 and 2^64-1")
    return value


def _receive_verdict() -> tuple:
    """The o5 allow/block assignments at the consensus-pinned width (bv[24])."""
    import tau_defs

    width = tau_defs.USER_POLICY_BV_WIDTH
    digits = width // 4
    allow = (
        f"(o5[t]:bv[{width}] = "
        f"{{ #x{tau_defs.USER_POLICY_ALLOW_VALUE:0{digits}x} }}:bv[{width}])"
    )
    block = (
        f"(o5[t]:bv[{width}] = "
        f"{{ #x{tau_defs.USER_POLICY_BLOCK_VALUE:0{digits}x} }}:bv[{width}])"
    )
    return allow, block


def _receive_unit(body: str) -> str:
    allow, block = _receive_verdict()
    return f"always ( {body} ? {allow} : {block} )."


def _receive_dedupe(pubkeys) -> list:
    seen, ordered = set(), []
    for raw in pubkeys:
        key = _receive_pubkey(raw)
        if key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered


def compose_receive_allow_list(pubkeys) -> str:
    """Inbound allow-list: allow when the sender (i3) is one of pubkeys.

    The same clause judges the owner's outbound pass, where i3 is the owner, so
    the owner's own key belongs in the list to keep outgoing transfers working.
    """
    keys = _receive_dedupe(pubkeys)
    if not keys:
        raise _PayloadError("an allow-list needs at least one sender pubkey")
    if len(keys) > 32:
        raise _PayloadError(
            "an allow-list may name at most 32 senders (the clause comparison limit)"
        )
    body = " || ".join(_receive_pubkey_literal("i3", k) for k in keys)
    if len(keys) > 1:
        body = f"( {body} )"
    return _receive_unit(body)


def compose_receive_max_hold(seconds, blocks) -> str:
    """Hold cap: allow when the hold is within the given bounds. A cap of 0 on a
    stream admits only payments that feed 0 there (instant for that park kind).
    Bounds whichever stream it reads; pass both to bound both park kinds."""
    seconds = _receive_cap(seconds, "--max-hold-seconds")
    blocks = _receive_cap(blocks, "--max-hold-blocks")
    if seconds is None and blocks is None:
        raise _PayloadError("give --max-hold-seconds and/or --max-hold-blocks")
    sec_idx, blk_idx = _receive_stream_indices()
    terms = []
    if seconds is not None:
        terms.append(_receive_hold_literal(sec_idx, seconds))
    if blocks is not None:
        terms.append(_receive_hold_literal(blk_idx, blocks))
    body = " && ".join(terms)
    if len(terms) > 1:
        body = f"( {body} )"
    return _receive_unit(body)


def compose_receive_combined(owner, send_to, allow_from, seconds, blocks) -> str:
    """One unit carrying an outbound whitelist, an inbound allow-list and hold
    caps. Each conjunct reads 'if this is my own send (i3 = me), skip; otherwise
    enforce', so the inbound rules never touch the owner's outgoing transfers.
    """
    owner = _receive_pubkey(owner)
    send_to = _receive_dedupe(send_to or [])
    allow_from = [k for k in _receive_dedupe(allow_from or []) if k != owner]
    seconds = _receive_cap(seconds, "--max-hold-seconds")
    blocks = _receive_cap(blocks, "--max-hold-blocks")
    if not send_to and not allow_from and seconds is None and blocks is None:
        raise _PayloadError(
            "give at least one of --send-to, --allow-from, "
            "--max-hold-seconds, --max-hold-blocks"
        )
    comparisons = (
        (1 + len(send_to) if send_to else 0)
        + (1 + len(allow_from) if allow_from else 0)
        + (2 if seconds is not None else 0)
        + (2 if blocks is not None else 0)
    )
    if comparisons > 32:
        raise _PayloadError(
            "this unit would exceed the 32-comparison clause limit; shorten the lists"
        )
    sec_idx, blk_idx = _receive_stream_indices()
    mine = _receive_pubkey_literal("i3", owner)
    conjuncts = []
    if send_to:
        listed = " || ".join(_receive_pubkey_literal("i4", k) for k in send_to)
        conjuncts.append(f"( !{mine} || {listed} )")
    if allow_from:
        terms = [mine] + [_receive_pubkey_literal("i3", k) for k in allow_from]
        conjuncts.append("( " + " || ".join(terms) + " )")
    if seconds is not None:
        conjuncts.append(f"( {mine} || {_receive_hold_literal(sec_idx, seconds)} )")
    if blocks is not None:
        conjuncts.append(f"( {mine} || {_receive_hold_literal(blk_idx, blocks)} )")
    return _receive_unit(" && ".join(conjuncts))


def _receive_register_guide(key_name) -> dict:
    name = key_name or "<name>"
    return {
        "direct": f"tau-testnet tx send --key {name} --rule-file receive.tau",
        "guarded": (
            f"tau-testnet policy change request --key {name} --kind set "
            "--file receive.tau --approver 18=<pubkey>"
        ),
        "note": (
            "Save the clause to receive.tau first. It replaces your current o5 "
            "clause; an o5 rule cannot share a transaction with transfers."
        ),
    }


def _emit_receive(args, clause: str, notes, key_name) -> int:
    guide = _receive_register_guide(key_name)
    if args.json:
        print_result(
            {"clause": clause, "register": guide, "notes": list(notes)},
            json_mode=True,
        )
        return EXIT_OK
    # The clause alone goes to stdout so it can be redirected to a file; the
    # registration guide and notes go to stderr.
    print(clause)
    print("Register this clause (it replaces your current o5 policy):", file=sys.stderr)
    print(f"  {guide['direct']}", file=sys.stderr)
    print("If your policy is guarded:", file=sys.stderr)
    print(f"  {guide['guarded']}", file=sys.stderr)
    for note in notes:
        print(f"note: {note}", file=sys.stderr)
    return EXIT_OK


def cmd_policy_receive_allow_list(args: argparse.Namespace) -> int:
    owner = None
    try:
        keys = list(args.address)
        if getattr(args, "key", None) or getattr(args, "privkey", None):
            _sk, owner = _resolve_signing_key(args)
            keys = [owner] + keys
        clause = compose_receive_allow_list(keys)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    notes = []
    if owner is None:
        notes.append(
            "no --key/--privkey given, so the list omits your own pubkey and this "
            "clause also blocks your outgoing transfers; add your key or use "
            "'policy receive combined'"
        )
    return _emit_receive(args, clause, notes, getattr(args, "key", None))


def cmd_policy_receive_max_hold(args: argparse.Namespace) -> int:
    try:
        clause = compose_receive_max_hold(args.max_hold_seconds, args.max_hold_blocks)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    notes = []
    if args.max_hold_seconds == 0 and args.max_hold_blocks is None:
        notes.append(
            "a seconds cap of 0 refuses time parks only; height parks feed i17=0 "
            "and pass. Add --max-hold-blocks 0 for instant-only."
        )
    if args.max_hold_blocks == 0 and args.max_hold_seconds is None:
        notes.append(
            "a blocks cap of 0 refuses height parks only; time parks feed i27=0 "
            "and pass. Add --max-hold-seconds 0 for instant-only."
        )
    return _emit_receive(args, clause, notes, None)


def cmd_policy_receive_combined(args: argparse.Namespace) -> int:
    try:
        _sk, owner = _resolve_signing_key(args)
        clause = compose_receive_combined(
            owner, args.send_to, args.allow_from,
            args.max_hold_seconds, args.max_hold_blocks,
        )
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    return _emit_receive(args, clause, [], getattr(args, "key", None))


def _add_policy_subparsers(sub) -> None:
    """`tau-testnet policy ...` -- the rule-change guard and its requests."""
    import tau_defs

    p_pol = sub.add_parser(
        "policy",
        parents=[_GLOBAL_PARENT],
        help="Guard your o5 policy with co-signers (guard, change requests)",
    )
    psub = p_pol.add_subparsers(dest="policy_command", required=True)
    common = [_GLOBAL_PARENT]
    default_expire = 2 * tau_defs.RULE_CHANGE_DELAY_BLOCKS

    def _key_group(parser, required=True):
        src = parser.add_mutually_exclusive_group(required=required)
        src.add_argument("--key", help="Logical name of a saved key")
        src.add_argument("--privkey", help="Private key (hex or decimal)")

    def _body_flags(parser, required):
        src = parser.add_mutually_exclusive_group(required=required)
        src.add_argument("--file", help="File containing the clause text")
        src.add_argument("--body", help="Clause text")

    def _request_flags(parser):
        parser.add_argument(
            "--approver", action="append", metavar="SLOT=PUBKEY",
            help="Approver for one slot, e.g. --approver 18=<pubkey>. Repeatable.",
        )
        window = parser.add_mutually_exclusive_group()
        window.add_argument(
            "--expire-in", type=_block_count, default=default_expire,
            help=(
                "Blocks the request may land in, from the next one (default: "
                f"%(default)s; at most {tau_defs.RULE_CHANGE_DELAY_BLOCKS} "
                "expires it before the time escape)"
            ),
        )
        window.add_argument("--expire-at-height", type=int,
                            help="Absolute expiry height (overrides --expire-in)")
        parser.add_argument("--fee", default=None, help=FEE_HELP)
        parser.add_argument(
            "--expiry", type=int, default=tx_mod.DEFAULT_EXPIRY_SECONDS,
            help="Seconds until expiration_time (default: %(default)s)",
        )
        parser.add_argument(
            "--preview", action="store_true",
            help="Ask the node what this request would need, and send nothing",
        )
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Sign and print the transaction, and send nothing",
        )

    p_guard = psub.add_parser("guard", parents=common,
                              help="Set, revoke or show the rule-change guard")
    gsub = p_guard.add_subparsers(dest="guard_command", required=True)

    p_gset = gsub.add_parser("set", parents=common,
                             help="Install a guard clause (rule-change kind 4)")
    _key_group(p_gset)
    _body_flags(p_gset, required=True)
    _request_flags(p_gset)
    p_gset.set_defaults(func=cmd_policy_guard_set)

    p_grev = gsub.add_parser("revoke", parents=common,
                             help="Remove the guard (rule-change kind 5)")
    _key_group(p_grev)
    _request_flags(p_grev)
    p_grev.set_defaults(func=cmd_policy_guard_revoke)

    p_gshow = gsub.add_parser("show", parents=common,
                              help="The guard clause on an account")
    p_gshow.add_argument("address", nargs="?", help="Address (default: your key's)")
    _key_group(p_gshow, required=False)
    p_gshow.set_defaults(func=cmd_policy_guard_show)

    p_change = psub.add_parser("change", parents=common,
                               help="Request or cancel a policy change")
    csub = p_change.add_subparsers(dest="change_command", required=True)

    p_creq = csub.add_parser(
        "request", parents=common,
        help="Request a policy change that the guard may park for co-signatures",
    )
    _key_group(p_creq)
    p_creq.add_argument("--kind", required=True, choices=sorted(_KIND_BY_NAME),
                        help="set (kind 1), revoke (kind 2) or accept an offer (kind 3)")
    _body_flags(p_creq, required=False)
    p_creq.add_argument("--offer-id", help="Offer to accept (64 hex), for --kind accept")
    _request_flags(p_creq)
    p_creq.set_defaults(func=cmd_policy_change_request)

    p_ccan = csub.add_parser("cancel", parents=common,
                             help="Cancel one of your parked requests (feeless)")
    _key_group(p_ccan)
    p_ccan.add_argument("--request-id", required=True, help="Request id (64 hex)")
    p_ccan.add_argument(
        "--expiry", type=int, default=tx_mod.DEFAULT_EXPIRY_SECONDS,
        help="Seconds until expiration_time (default: %(default)s)",
    )
    p_ccan.add_argument("--expire-in", type=_block_count, default=1000,
                        help="Blocks the cancel may land in, from the next one")
    p_ccan.add_argument("--expire-at-height", type=int,
                        help="Absolute expiry height (overrides --expire-in)")
    p_ccan.set_defaults(func=cmd_policy_change_cancel)

    # --- receive: compose an inbound policy clause (issues #47, #76) ---
    p_recv = psub.add_parser(
        "receive", parents=common,
        help="Compose an inbound policy clause (allow-list, hold caps)",
    )
    rsub = p_recv.add_subparsers(dest="receive_command", required=True)

    p_al = rsub.add_parser(
        "allow-list", parents=common,
        help="Allow incoming payments only from the listed senders",
    )
    p_al.add_argument("address", nargs="+", help="Sender public key (96 hex); repeatable")
    _key_group(p_al, required=False)
    p_al.set_defaults(func=cmd_policy_receive_allow_list)

    p_mh = rsub.add_parser(
        "max-hold", parents=common,
        help="Cap how long a payment to you may be held (0 = instant only)",
    )
    p_mh.add_argument(
        "--max-hold-seconds", type=int, default=None,
        help="Maximum hold in seconds (i17); 0 refuses every time park",
    )
    p_mh.add_argument(
        "--max-hold-blocks", type=int, default=None,
        help="Maximum hold in blocks (i27); 0 refuses every height park",
    )
    p_mh.set_defaults(func=cmd_policy_receive_max_hold)

    p_cb = rsub.add_parser(
        "combined", parents=common,
        help="One unit: outbound whitelist + inbound allow-list + hold caps",
    )
    _key_group(p_cb, required=True)
    p_cb.add_argument(
        "--send-to", action="append", default=None, metavar="PUBKEY",
        help="Outbound whitelist recipient (96 hex); repeatable",
    )
    p_cb.add_argument(
        "--allow-from", action="append", default=None, metavar="PUBKEY",
        help="Inbound allow-list sender (96 hex); repeatable",
    )
    p_cb.add_argument(
        "--max-hold-seconds", type=int, default=None,
        help="Maximum incoming hold in seconds (i17)",
    )
    p_cb.add_argument(
        "--max-hold-blocks", type=int, default=None,
        help="Maximum incoming hold in blocks (i27)",
    )
    p_cb.set_defaults(func=cmd_policy_receive_combined)


# --- Retractable transfers --------------------------------------------------


def _release_point(args, tip: int, now: int) -> dict:
    """The release kwargs for the builder from whichever --release-* flag is set."""
    if getattr(args, "release_at_height", None) is not None:
        height = int(args.release_at_height)
    elif getattr(args, "release_in", None) is not None:
        if not tip:
            tip = _tip_height(args)
        height = tip + 1 + int(args.release_in)
    else:
        height = None
    if height is not None:
        if not tip:
            tip = _tip_height(args)
        if height <= tip + 1:
            raise _PayloadError(
                f"release height {height} is not after the next block ({tip + 1}); "
                "the park would be mined at or past its release."
            )
        return {"release_at_height": height}

    if getattr(args, "release_at_time", None) is not None:
        when = int(args.release_at_time)
    else:
        when = now + int(args.release_after)
    if when <= now + 1:
        raise _PayloadError(f"release time {when} is already (almost) past.")
    return {"release_at_time": when}


def cmd_retractable_send(args: argparse.Namespace) -> int:
    from consensus.retractable import RetractableShapeError, parse_retractable_transfer

    created = {}

    def _build(sender_pubkey, sequence_number, expire_at_height, tip):
        now = int(_now())
        payload = tx_mod.build_retractable_transfer_tx(
            sender_pubkey=sender_pubkey,
            sequence_number=sequence_number,
            expiration_time=now + args.expiry,
            expire_at_height=expire_at_height,
            recipient_pubkey=args.to,
            amount=int(args.amount),
            **_release_point(args, tip, now),
        )
        try:
            created["id"] = parse_retractable_transfer(payload).retractable_id.hex()
        except RetractableShapeError as exc:
            raise _PayloadError(str(exc))
        return payload

    status = _submit_rule_tx(args, _build, pass_tip=True)
    if status == EXIT_OK and created.get("id"):
        print(f"retractable id: {created['id']}", file=sys.stderr if args.json else sys.stdout)
    return status


def cmd_retractable_retract(args: argparse.Namespace) -> int:
    def _build(sender_pubkey, sequence_number, expire_at_height):
        return tx_mod.build_retract_transfer_tx(
            sender_pubkey=sender_pubkey,
            sequence_number=sequence_number,
            expiration_time=int(_now()) + args.expiry,
            expire_at_height=expire_at_height,
            retractable_id=args.retractable_id,
        )

    return _submit_rule_tx(args, _build)


def cmd_retractable_list(args: argparse.Namespace) -> int:
    try:
        address = _address_or_key(args)
    except _PayloadError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    return _simple_query(args, f"getretractables {address} {getattr(args, 'role', 'all')}")


def cmd_retractable_show(args: argparse.Namespace) -> int:
    return _simple_query(args, f"getretractable {args.retractable_id}")


def cmd_retractable_id(args: argparse.Namespace) -> int:
    from consensus.retractable import RetractableShapeError, parse_retractable_transfer

    fields = {
        "sender_pubkey": args.from_pubkey.strip().lower(),
        "recipient_pubkey": args.to.strip().lower(),
        "amount": int(args.amount),
        "sequence_number": int(args.sequence),
    }
    if args.release_at_height is not None:
        fields["release_at_height"] = int(args.release_at_height)
    else:
        fields["release_at_time"] = int(args.release_at_time)
    try:
        rid = parse_retractable_transfer(fields).retractable_id.hex()
    except RetractableShapeError as exc:
        print_error(str(exc))
        return EXIT_LOCAL
    if args.json:
        print_result({"retractable_id": rid, "input_echo": fields}, json_mode=True)
    else:
        print(rid)
    return EXIT_OK


def _add_retractable_subparsers(sub) -> None:
    """`tau-testnet retractable ...` -- park a transfer until a release point."""
    p_ret = sub.add_parser(
        "retractable",
        parents=[_GLOBAL_PARENT],
        help="Retractable transfers (send, retract, inspect)",
    )
    rsub = p_ret.add_subparsers(dest="retractable_command", required=True)
    common = [_GLOBAL_PARENT]

    def _key_group(parser, required=True):
        src = parser.add_mutually_exclusive_group(required=required)
        src.add_argument("--key", help="Logical name of a saved key")
        src.add_argument("--privkey", help="Private key (hex or decimal)")

    def _tx_flags(parser, fee=True):
        if fee:
            parser.add_argument("--fee", default=None, help=FEE_HELP)
        parser.add_argument(
            "--expiry", type=int, default=tx_mod.DEFAULT_EXPIRY_SECONDS,
            help="Seconds until expiration_time (default: %(default)s)",
        )
        parser.add_argument("--expire-in", type=_block_count, default=1000,
                            help="Blocks the transaction may land in, from the next one")
        parser.add_argument("--expire-at-height", type=int,
                            help="Absolute expiry height (overrides --expire-in)")

    p_send = rsub.add_parser(
        "send", parents=common,
        help="Escrow a transfer until a release point; retract it before then",
    )
    _key_group(p_send)
    p_send.add_argument("--to", required=True, help="Recipient public key (96 hex)")
    p_send.add_argument("--amount", required=True, type=int, help="Amount to transfer")
    release = p_send.add_mutually_exclusive_group(required=True)
    release.add_argument("--release-in", type=_block_count, metavar="BLOCKS",
                         help="Release this many blocks after the next one")
    release.add_argument("--release-at-height", type=int, metavar="HEIGHT",
                         help="Release in the first block at or past this height")
    release.add_argument("--release-at-time", type=int, metavar="UNIX",
                         help="Release in the first block stamped at or past this time")
    release.add_argument("--release-after", type=_block_count, metavar="SECONDS",
                         help="Release this many seconds from now")
    _tx_flags(p_send)
    p_send.set_defaults(func=cmd_retractable_send)

    p_back = rsub.add_parser(
        "retract", parents=common,
        help="Take an escrowed transfer back before its release point",
    )
    _key_group(p_back)
    p_back.add_argument("retractable_id", help="Retractable id (64 hex)")
    # A retract is fee-exempt, so a fee limit changes nothing.
    _tx_flags(p_back, fee=False)
    p_back.set_defaults(func=cmd_retractable_retract)

    p_list = rsub.add_parser("list", parents=common,
                             help="Open retractable transfers for an address")
    p_list.add_argument("--address", help="Address (default: your key's)")
    _key_group(p_list, required=False)
    p_list.add_argument("--role", choices=["in", "out", "all"], default="all")
    p_list.set_defaults(func=cmd_retractable_list)

    p_show = rsub.add_parser("show", parents=common, help="One retractable transfer")
    p_show.add_argument("retractable_id", help="Retractable id (64 hex)")
    p_show.set_defaults(func=cmd_retractable_show)

    p_rid = rsub.add_parser("id", parents=common,
                            help="Derive a retractable id without submitting")
    p_rid.add_argument("--from-pubkey", required=True, help="Sender public key")
    p_rid.add_argument("--to", required=True, help="Recipient public key")
    p_rid.add_argument("--amount", required=True, type=int)
    p_rid.add_argument("--sequence", required=True, type=int)
    rid_release = p_rid.add_mutually_exclusive_group(required=True)
    rid_release.add_argument("--release-at-height", type=int)
    rid_release.add_argument("--release-at-time", type=int)
    p_rid.set_defaults(func=cmd_retractable_id)


def _add_rule_subparsers(sub) -> None:
    """`tau-testnet rule ...` -- send, review, accept or reject shared rules."""
    p_rule = sub.add_parser(
        "rule",
        parents=[_GLOBAL_PARENT],
        help="Share Tau rules with other users (send, check, accept, reject)",
    )
    rsub = p_rule.add_subparsers(dest="rule_command", required=True)
    common = [_GLOBAL_PARENT]

    def _key_group(parser):
        src = parser.add_mutually_exclusive_group(required=True)
        src.add_argument("--key", help="Logical name of a saved key")
        src.add_argument("--privkey", help="Private key (hex or decimal)")

    def _rule_source(parser):
        src = parser.add_mutually_exclusive_group(required=True)
        src.add_argument("--rule", help="Tau rule text")
        src.add_argument("--rule-file", help="File containing the Tau rule text")

    def _tx_flags(parser):
        parser.add_argument("--fee", default=None, help=FEE_HELP)
        parser.add_argument(
            "--expiry",
            type=int,
            default=tx_mod.DEFAULT_EXPIRY_SECONDS,
            help="Seconds until expiration_time (default: %(default)s)",
        )

    # --- offer ---
    p_offer = rsub.add_parser(
        "offer", parents=common, help="Send a rule to another user for review"
    )
    _key_group(p_offer)
    _rule_source(p_offer)
    p_offer.add_argument("--to", required=True, help="Recipient public key (96 hex)")
    window = p_offer.add_mutually_exclusive_group()
    window.add_argument(
        "--expire-in",
        type=_block_count,
        default=1000,
        help="Blocks the offer may land in, from the next one (default: %(default)s)",
    )
    window.add_argument(
        "--expire-at-height", type=int, help="Absolute height at which the offer expires"
    )
    _tx_flags(p_offer)
    p_offer.set_defaults(func=cmd_rule_offer)

    # --- list ---
    p_list = rsub.add_parser(
        "list", parents=common, help="List rule offers involving an address"
    )
    p_list.add_argument(
        "address", nargs="?", help="Address to inspect (defaults to --key/--privkey owner)"
    )
    p_list.add_argument("--key", help="Logical name of a saved key")
    p_list.add_argument("--privkey", help="Private key (hex or decimal)")
    p_list.add_argument(
        "--role", choices=["in", "out", "all"], default="all",
        help="Show incoming, outgoing, or both (default: %(default)s)",
    )
    p_list.set_defaults(func=cmd_rule_list)

    # --- show ---
    p_show = rsub.add_parser(
        "show", parents=common, help="Show one offer in full, including its rule text"
    )
    p_show.add_argument("offer_id", help="Offer id (64 hex)")
    p_show.set_defaults(func=cmd_rule_show)

    # --- check ---
    p_check = rsub.add_parser(
        "check", parents=common,
        help="Conflict status for an offer (advisory, node-local)",
    )
    p_check.add_argument("offer_id", help="Offer id (64 hex)")
    p_check.set_defaults(func=cmd_rule_check)

    # --- accept ---
    p_accept = rsub.add_parser(
        "accept", parents=common,
        help="Accept an offer into your specification (prints the conflict report first)",
    )
    _key_group(p_accept)
    p_accept.add_argument("offer_id", help="Offer id (64 hex)")
    p_accept.add_argument(
        "--rule-file",
        help="Override the rule text (must match the offered bytes exactly)",
    )
    p_accept.add_argument(
        "--yes", action="store_true",
        help="Accept even when the conflict check reports warn or conflict",
    )
    _tx_flags(p_accept)
    p_accept.set_defaults(func=cmd_rule_accept)

    # --- reject ---
    p_reject = rsub.add_parser("reject", parents=common, help="Reject an offer")
    _key_group(p_reject)
    p_reject.add_argument("offer_id", help="Offer id (64 hex)")
    _tx_flags(p_reject)
    p_reject.set_defaults(func=cmd_rule_reject)

    # --- offer-id ---
    p_oid = rsub.add_parser(
        "offer-id", parents=common, help="Derive an offer id without submitting"
    )
    _rule_source(p_oid)
    p_oid.add_argument("--from-pubkey", required=True, dest="from_pubkey",
                       help="Offerer public key (96 hex)")
    p_oid.add_argument("--to", required=True, help="Recipient public key (96 hex)")
    p_oid.add_argument("--expire-at-height", type=int, required=True,
                       help="Absolute height at which the offer expires")
    p_oid.set_defaults(func=cmd_rule_offer_id)


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
