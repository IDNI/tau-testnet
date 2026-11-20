"""The raw application-rules accumulation, kept for compatibility.

This is the submitted rule text, append-only: it is NOT the rules in
force, because a later revision can displace part of an earlier one and
the accumulation still shows both. For the effective spec -- the engine's
normalized text after pointwise revision -- use `getactiverules`
(issue #42).
"""
import api_response


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 1:
        return api_response.error_response(
            "gettaustate", "Usage: gettaustate", "INVALID_PARAMS"
        )

    state = container.chain_state.get_rules_state()
    return api_response.success_response("gettaustate", {"rules_state": state or ""})
