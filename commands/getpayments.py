"""Read programmable-payment books and the capability report."""
import api_response

_CMD = "getpayments"


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) < 2:
        return api_response.error_response(
            _CMD,
            "Usage: getpayments capability|standing|allowance|route|payout [id]",
            "INVALID_PARAMS",
        )
    kind = parts[1].strip().lower()
    import chain_state
    from consensus.payments import CAPABILITY, public_views

    lm = getattr(chain_state, "_lifecycle_manager", None)
    book = getattr(lm, "programmable", None)
    if book is None:
        return api_response.error_response(_CMD, "Payments are not loaded.", "PAYMENTS_UNAVAILABLE")
    if kind == "capability":
        return api_response.success_response(_CMD, dict(CAPABILITY))
    views = public_views(book)
    ident = parts[2].strip().lower() if len(parts) > 2 else ""
    table = {
        "standing": "standing",
        "allowance": "allowances",
        "allowances": "allowances",
        "route": "routes",
        "routes": "routes",
        "payout": "payouts",
        "payouts": "payouts",
    }.get(kind)
    if table is None:
        return api_response.error_response(_CMD, f"Unknown payments query '{kind}'.", "INVALID_PARAMS")
    rows = views[table]
    if not ident:
        return api_response.success_response(_CMD, {"kind": kind, "rows": rows})
    matched = [
        row for row in rows
        if ident in (
            str(row.get("id", "")),
            str(row.get("owner", "")),
            str(row.get("payer", "")),
            str(row.get("grantor", "")),
            str(row.get("grantee", "")),
        )
    ]
    return api_response.success_response(_CMD, {"kind": kind, "rows": matched})
