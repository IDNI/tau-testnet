"""
Isolated rule-compile worker.

Runs `tau_native.TauInterface.compile_revisions_isolated` in a *fresh* process
so a hung or non-terminating native Tau compile can be killed by SIGKILL from
the parent (see `tau_native.compile_revisions_isolated_subprocess`). Nothing
here touches the parent server's live interpreter state.

Protocol:
  stdin  : JSON {"consensus_rules_text": str, "revisions": [str, ...]}
  stdout : a single line `__TAU_COMPILE_RESULT__<json>` where <json> is
           {"ok": bool, "error": str|null}. Native compile chatter may precede
           it on stdout; the parent scans for the sentinel prefix.
"""

import json
import sys

RESULT_SENTINEL = "__TAU_COMPILE_RESULT__"


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        consensus_rules_text = payload.get("consensus_rules_text", "") or ""
        revisions = payload.get("revisions", []) or []
    except Exception as exc:  # malformed request from parent
        sys.stdout.write(
            RESULT_SENTINEL
            + json.dumps({"ok": False, "error": f"worker bad input: {exc}"})
            + "\n"
        )
        sys.stdout.flush()
        return 0

    try:
        import tau_native

        # Surface native-unavailability distinctly so the parent falls back to
        # the live validation path instead of rejecting the transaction.
        tau_native.load_tau_module()

        err = tau_native.TauInterface.compile_revisions_isolated(
            consensus_rules_text, revisions
        )
        result = {"ok": err is None, "error": err}
    except ImportError as exc:
        result = {"ok": False, "unavailable": True, "error": f"native tau unavailable: {exc}"}
    except Exception as exc:
        result = {"ok": False, "error": f"worker compile crashed: {exc}"}

    sys.stdout.write(RESULT_SENTINEL + json.dumps(result) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
