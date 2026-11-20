"""One account's programmable-payments status (Bounty 01): its standing
authorizations, receive route, payout rules and grants, read from the
canonical tip's payment books."""
import re

import api_response

_CMD = "getpayments"
_ADDRESS_RE = re.compile(r"^[0-9a-f]{96}$")


def _books(container):
    chain_state = container.chain_state
    lm = getattr(chain_state, "_lifecycle_manager", None)
    return getattr(lm, "programmable_payments", None)


def _authorization_view(auth_id, state) -> dict:
    return {
        "authorization_id": auth_id.hex(),
        "terms": state.terms.to_dict(),
        "status": state.status,
        "settled_periods": sorted(state.settled),
        "skipped_periods": sorted(state.skipped),
        "cumulative_spent": state.cumulative_spent,
    }


def _grant_view(grant_id, state) -> dict:
    return {
        "grant_id": grant_id.hex(),
        "terms": state.terms.to_dict(),
        "status": state.status,
        "held": state.held,
        "drawn_total": state.drawn_total,
        "refunded": state.refunded,
        "refund_fee_paid": state.refund_fee_paid,
    }


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <address>", "INVALID_PARAMS"
        )
    address = parts[1].strip().lower()
    if not _ADDRESS_RE.match(address):
        return api_response.error_response(
            _CMD, "address must be 96 lowercase hex characters.", "INVALID_PARAMS"
        )
    books = _books(container)
    if books is None:
        return api_response.error_response(
            _CMD, "Programmable payments are not available on this node.",
            "PAYMENTS_UNAVAILABLE",
        )

    authorizations = [
        _authorization_view(auth_id, state)
        for auth_id, state in sorted(books.standing.authorizations.items())
        if state.terms.payer == address or state.terms.payee == address
    ]
    route_terms = books.routes.get(address)
    route = None
    if route_terms is not None:
        route = {"route_id": route_terms.route_id.hex(),
                 "terms": route_terms.to_dict()}
    payout_rules = [
        {
            "payout_rule_id": rule_id.hex(),
            "terms": state.terms.to_dict(),
            "settled_events": {
                event_id: {"legs": [[p, a] for p, a in r.legs], "total": r.total}
                for event_id, r in sorted(state.settled_events.items())
            },
            "period_spent": {
                str(k): v for k, v in sorted(state.period_spent.items())
            },
        }
        for rule_id, state in sorted(books.payouts.rules.items())
        if state.terms.owner == address
    ]
    grants = [
        _grant_view(grant_id, state)
        for grant_id, state in sorted(books.grants.grants.items())
        if address in (state.terms.grantor, state.terms.grantee,
                       state.terms.refund_recipient)
    ]
    shared_cap = None
    cap_state = books.grants.shared_cap_state(address)
    if cap_state is not None:
        shared_cap = {"limit": cap_state.limit, "spent": cap_state.spent}

    return api_response.success_response(_CMD, {
        "address": address,
        "authorizations": authorizations,
        "route": route,
        "payout_rules": payout_rules,
        "grants": grants,
        "shared_cap": shared_cap,
    })
