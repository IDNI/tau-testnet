#!/usr/bin/env python3
"""Google-Authenticator bot: signs a parked transfer once a valid TOTP arrives.

RFC 6238 TOTP implemented from the standard library — `hmac`, `hashlib`,
`struct`, `base64` — so this adds NO dependency and is byte-compatible with
Google Authenticator, Authy, 1Password and the rest. There is no Google API call
anywhere; "google auth" is the algorithm, and the algorithm is thirty lines.

WHY THE CODE NEVER GOES ON CHAIN
--------------------------------
A TOTP is six digits. On-chain it is readable by everyone for its whole validity
window, and a hash of it is brute-forceable in microseconds — 10^6 candidates.
So the code travels to THIS process over its own endpoint, is verified here, and
what goes on chain is the bot's BLS signature, which is what the sender's Tau
policy actually tests.

The chain does support putting a code in a request's custom input, because the
sender may want to attach data an approver can read. The CLI warns before doing
it and this bot accepts it, but the endpoint is the path worth using.

    # enrol a sender (prints the otpauth:// URI for their phone)
    approval_bot_totp.py --enroll <sender-pubkey> --privkey-file bot.key

    # run
    approval_bot_totp.py --privkey-file bot.key
    # then, from the sender's machine:
    printf '{"request_id":"<id>","code":"123456"}\\n' | nc 127.0.0.1 65440
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import stat
import struct
import threading
import time

from approval_bot_common import (
    ApproverBot,
    NodeClient,
    Signer,
    base_arg_parser,
    configure_logging,
    load_privkey,
    logger,
    run_bot,
)

DEFAULT_ENROLLMENT_DIR = os.path.expanduser("~/.tau-approval-bot")
DEFAULT_ENDPOINT_PORT = 65440
TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
# One step either side, the usual allowance for clock skew and typing time.
TOTP_WINDOW_STEPS = 1


# --- RFC 6238 ---------------------------------------------------------------

def totp_at(secret_b32: str, timestamp: int, step=TOTP_STEP_SECONDS,
            digits=TOTP_DIGITS) -> str:
    """The code for one time step. HMAC-SHA1, as Google Authenticator uses."""
    padded = secret_b32.strip().replace(" ", "").upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = struct.pack(">Q", int(timestamp) // step)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def verify_totp(secret_b32: str, code: str, *, now=None,
                window=TOTP_WINDOW_STEPS) -> int | None:
    """The matching time step, or None. Constant-time comparison per candidate."""
    if not isinstance(code, str) or not code.strip().isdigit():
        return None
    candidate = code.strip().zfill(TOTP_DIGITS)
    now = int(now if now is not None else time.time())
    for delta in range(-window, window + 1):
        moment = now + delta * TOTP_STEP_SECONDS
        if hmac.compare_digest(totp_at(secret_b32, moment), candidate):
            return moment // TOTP_STEP_SECONDS
    return None


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def otpauth_uri(secret_b32: str, label: str, issuer="tau-testnet") -> str:
    from urllib.parse import quote

    return (f"otpauth://totp/{quote(issuer)}:{quote(label)}?secret={secret_b32}"
            f"&issuer={quote(issuer)}&algorithm=SHA1&digits={TOTP_DIGITS}"
            f"&period={TOTP_STEP_SECONDS}")


# --- enrolment store --------------------------------------------------------

class EnrollmentStore:
    """sender pubkey -> shared TOTP secret. Never leaves this machine."""

    def __init__(self, directory=DEFAULT_ENROLLMENT_DIR):
        self.directory = os.path.expanduser(directory)
        self.path = os.path.join(self.directory, "enrollments.json")

    def _ensure_dir(self):
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        os.chmod(self.directory, 0o700)

    def check_permissions(self):
        """Refuse to run on a loose store rather than warn about it.

        These secrets are equivalent to the second factor itself: anyone who can
        read them can mint valid codes forever.
        """
        if not os.path.exists(self.path):
            return
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        if mode & 0o077:
            raise SystemExit(
                f"{self.path} is mode {mode:03o}; TOTP secrets must not be "
                f"group- or world-readable. chmod 600 it."
            )

    def load(self) -> dict:
        if not os.path.exists(self.path):
            return {}
        self.check_permissions()
        with open(self.path) as handle:
            try:
                return json.load(handle)
            except ValueError:
                logger.error("%s is not valid JSON; treating as empty", self.path)
                return {}

    def save(self, data: dict):
        self._ensure_dir()
        tmp = self.path + ".tmp"
        with open(tmp, "w") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def enroll(self, pubkey: str) -> str:
        data = self.load()
        secret = new_secret()
        data[pubkey.lower()] = secret
        self.save(data)
        return secret

    def secret_for(self, pubkey: str):
        return self.load().get((pubkey or "").lower())


# --- the side-channel endpoint ---------------------------------------------

class _RateLimiter:
    """Token bucket per source, so a brute-force attempt costs time.

    Six digits is 10^6 candidates: without this, an attacker who can reach the
    endpoint walks the space in seconds.
    """

    def __init__(self, burst=5, refill_per_sec=0.2):
        self.burst = float(burst)
        self.refill = float(refill_per_sec)
        self._state: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._state.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.refill)
            if tokens < 1.0:
                self._state[key] = (tokens, now)
                return False
            self._state[key] = (tokens - 1.0, now)
            return True


class CodeEndpoint:
    """Loopback line-protocol listener: {"request_id": ..., "code": "123456"}."""

    def __init__(self, bot, host="127.0.0.1", port=DEFAULT_ENDPOINT_PORT):
        self.bot = bot
        self.host = host
        self.port = port
        self.limiter = _RateLimiter()
        self._thread = None

    def start(self):
        if self.host not in ("127.0.0.1", "::1", "localhost"):
            logger.warning(
                "endpoint bound to %s, not loopback: a TOTP code will cross the "
                "network in cleartext. Only do this behind a TLS terminator.",
                self.host,
            )
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        logger.info("code endpoint listening on %s:%d", self.host, self.port)

    def _serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(16)
        while True:
            try:
                conn, addr = srv.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr),
                             daemon=True).start()

    def _handle(self, conn, addr):
        try:
            conn.settimeout(10.0)
            raw = conn.recv(4096).decode(errors="replace").strip()
            source = addr[0] if addr else "?"
            if not self.limiter.allow(source):
                conn.sendall(b'{"status":"error","error":"rate limited"}\n')
                return
            try:
                message = json.loads(raw)
                request_id = str(message["request_id"]).lower()
                code = str(message["code"])
            except Exception:
                conn.sendall(b'{"status":"error","error":"expected '
                             b'{\\"request_id\\":...,\\"code\\":...}"}\n')
                return
            ok, detail = self.bot.submit_code(request_id, code)
            conn.sendall(json.dumps(
                {"status": "ok" if ok else "error", "detail": detail}).encode() + b"\n")
        except Exception:
            logger.debug("endpoint connection failed", exc_info=True)
        finally:
            try:
                conn.close()
            except Exception:
                pass


# --- the bot ----------------------------------------------------------------

class TotpBot(ApproverBot):
    name = "totp"

    def __init__(self, *args, store: EnrollmentStore, accept_onchain_code=False,
                 **kwargs):
        super().__init__(*args, **kwargs)
        self.store = store
        self.accept_onchain_code = accept_onchain_code
        # request_id -> the time step a code was accepted for. One-time use:
        # a code replayed for a DIFFERENT request must not work, and the same
        # code must not authorise the same request twice.
        self._accepted: dict[str, int] = {}
        self._used_steps: set[tuple[str, int]] = set()
        self._lock = threading.Lock()
        self._pending: dict[str, dict] = {}

    def submit_code(self, request_id: str, code: str):
        """Called from the endpoint thread. Returns (ok, detail)."""
        with self._lock:
            request = self._pending.get(request_id)
        if request is None:
            return False, "no such request awaiting this bot"
        sender = str(request.get("sender_pubkey", "")).lower()
        secret = self.store.secret_for(sender)
        if not secret:
            return False, f"sender {sender[:10]} is not enrolled with this bot"
        step = verify_totp(secret, code)
        if step is None:
            logger.warning("rejected code for %s from an enrolled sender",
                           request_id[:16])
            return False, "invalid code"
        with self._lock:
            if (sender, step) in self._used_steps:
                # Bound to (sender, step), so one code cannot be replayed onto a
                # second request inside its own validity window.
                return False, "code already used"
            self._used_steps.add((sender, step))
            self._accepted[request_id] = step
        logger.info("accepted a valid code for %s", request_id[:16])
        return True, "accepted; the vote will be cast on the next poll"

    def decide(self, request: dict):
        request_id = request["request_id"]
        with self._lock:
            self._pending[request_id] = request
            accepted = request_id in self._accepted

        if accepted:
            return True, "valid TOTP received"

        if self.accept_onchain_code:
            # Opt-in, and never the default: a code in a custom input is public
            # for its whole validity window.
            sender = str(request.get("sender_pubkey", "")).lower()
            secret = self.store.secret_for(sender)
            for stream, value in (request.get("custom_inputs") or {}).items():
                if secret and verify_totp(secret, str(value)) is not None:
                    logger.warning(
                        "accepting a code from PUBLIC custom input i%s on %s; "
                        "prefer the endpoint", stream, request_id[:16])
                    return True, "valid TOTP in custom input (public)"

        # Deferring, not declining: the code has simply not arrived yet, and
        # declining would waste the request.
        return None


def main(argv=None):
    parser = base_arg_parser(__doc__.splitlines()[0])
    parser.add_argument("--enroll", metavar="SENDER_PUBKEY",
                        help="Enrol a sender and print their otpauth:// URI")
    parser.add_argument("--enrollment-dir", default=DEFAULT_ENROLLMENT_DIR)
    parser.add_argument("--bind", default="127.0.0.1",
                        help="Code endpoint bind address (loopback by default)")
    parser.add_argument("--endpoint-port", type=int, default=DEFAULT_ENDPOINT_PORT)
    parser.add_argument("--no-endpoint", action="store_true",
                        help="Do not listen for codes (custom-input mode only)")
    parser.add_argument("--accept-onchain-code", action="store_true",
                        help="Also accept a code from a request's PUBLIC custom input")
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    store = EnrollmentStore(args.enrollment_dir)
    store.check_permissions()

    if args.enroll:
        secret = store.enroll(args.enroll)
        print("Enrolled", args.enroll[:16] + "...")
        print("Secret :", secret)
        print("URI    :", otpauth_uri(secret, args.enroll[:16]))
        print("\nAdd the URI to your authenticator app. The secret stays on this")
        print("machine and never touches the chain.")
        return 0

    signer = Signer(load_privkey(args))
    client = NodeClient(args.host, args.port)
    bot = TotpBot(client, signer, dry_run=args.dry_run, poll_seconds=args.poll,
                  store=store, accept_onchain_code=args.accept_onchain_code)

    if not args.no_endpoint:
        CodeEndpoint(bot, args.bind, args.endpoint_port).start()

    return run_bot(bot, args.once)


if __name__ == "__main__":
    raise SystemExit(main())
