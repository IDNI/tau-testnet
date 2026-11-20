"""What the programmable-payments capability surface reports (#34 case 9,
#35 case 8): the schedule, routing and payout semantics a wallet checks
BEFORE offering either feature. Every value is read from the constants
the payment books enforce, so the report cannot drift from admission and
apply behaviour."""
import api_response
from consensus.payments import capability_report

_CMD = "getpaymentcapabilities"


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 1:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD}", "INVALID_PARAMS"
        )
    return api_response.success_response(_CMD, capability_report())
