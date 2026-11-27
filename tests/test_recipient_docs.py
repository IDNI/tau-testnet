"""The rules and numbers the documentation shows for recipient controls are the
ones the code gives.

Every rule shown below its `policy receive-rule` command line must be what that
command prints. Every rule shown as written by hand must be one of the builders
in `recipient_rules`, which the native tests hold to the real engine. The
ceilings, the codes and the worked numbers are compared with their source.
"""
import pathlib
import re
import shlex

import pytest

import recipient_rules as rules
import tau_defs
from consensus import recipient_policy
from test_cli_policy import _run

REPO = pathlib.Path(__file__).resolve().parent.parent
GUIDE = REPO / "docs" / "recipient_controls.md"
README = REPO / "README.md"
EVERY_DOC = [README, REPO / "WALLET_USAGE.md"] + sorted((REPO / "docs").glob("*.md"))
KEYS = {"<ALICE>": "a" * 96, "<SHOP>": "5" * 96}
COMMAND = "$ tau-testnet policy receive-rule "


def _flat(text: str) -> str:
    return " ".join(text.split())


def _with_keys(text: str) -> str:
    for name, key in KEYS.items():
        text = text.replace(name, key)
    return text


def _code_blocks(path: pathlib.Path):
    return re.findall(r"```[a-z]*\n(.*?)```", path.read_text(encoding="utf-8"), flags=re.DOTALL)


def _shown_with_their_command():
    """(document, flags, rule) for every command line shown with its output."""
    found = []
    for path in (GUIDE, README):
        for block in _code_blocks(path):
            if COMMAND not in block:
                continue
            for part in block.split(COMMAND)[1:]:
                flags, _, rule = part.partition("\n")
                found.append((path.name, flags.strip(), _flat(rule)))
    return found


def _shown_by_hand():
    return [_flat(block) for block in _code_blocks(GUIDE)
            if block.lstrip().startswith("always")]


WRITTEN = _shown_with_their_command()


def test_the_documents_show_rules_at_all():
    """The checks below prove nothing if the parser finds nothing."""
    assert len(WRITTEN) >= 12
    assert len(_shown_by_hand()) == 3


@pytest.mark.parametrize("document,flags,shown", WRITTEN,
                         ids=[f"{doc}: {flags}"[:70] for doc, flags, _ in WRITTEN])
def test_a_rule_shown_with_its_command_is_what_the_command_prints(document, flags, shown):
    rc, out, err = _run(["policy", "receive-rule"] + shlex.split(_with_keys(flags)), [], [])
    assert rc == 0, err
    assert _flat(out) == _with_keys(shown)


def test_the_rules_shown_by_hand_are_the_ones_the_engine_tests_run():
    shop, alice = KEYS["<SHOP>"], KEYS["<ALICE>"]
    tested = {
        _flat("always " + rules.one_unit(shop, alice, 600) + "."),
        _flat("always " + rules.needs_reference(30) + "."),
        _flat("always " + rules.hold_plus_recall(3_600) + "."),
    }
    assert {_with_keys(rule) for rule in _shown_by_hand()} == tested


def test_every_refusal_code_is_documented():
    guide = GUIDE.read_text(encoding="utf-8")
    codes = set(recipient_policy.REFUSAL_CODES.values()) | {
        "RECIPIENT_POLICY", "RECIPIENT_POLICY_INACTIVE"}
    for code in sorted(codes):
        assert f"`{code}`" in guide, code
    for condition in recipient_policy.REFUSAL_CODES:
        assert f"`{condition}`" in guide, condition


def test_the_documented_ceilings_are_the_records():
    guide = GUIDE.read_text(encoding="utf-8")
    assert f"{tau_defs.RECEIVE_LIMIT_CEILING:,}" in guide
    assert f"{tau_defs.RECEIVE_PERIOD_CEILING_SECONDS:,} seconds (366 days)" in guide
    assert tau_defs.RECEIVE_PERIOD_CEILING_SECONDS == 366 * 86_400
    assert f"{tau_defs.RECEIVE_PERIOD_CEILING_BLOCKS:,} blocks" in guide
    assert str(tau_defs.RECEIVE_NEVER) in guide
    assert '["i17", "i50", "i51", "i52", "i53", "i54"]' in guide
    assert [f"i{index}" for index in tau_defs.RECEIVE_RECORD_INDICES] == [
        "i17", "i50", "i51", "i52", "i53", "i54"]


def test_the_worked_numbers_of_the_limit_comparison():
    """500 a week against a limit over 30 days: 2,500 on the strict reading,
    2,143 on the average one, as the guide says."""
    guide = GUIDE.read_text(encoding="utf-8")
    week, month, allowance = 604_800, 2_592_000, 500
    strict = rules.written_model(min_allowance=allowance, per_seconds=week)
    average = rules.written_model(min_allowance=allowance, per_seconds=week, average=True)

    def accepts(model, cap):
        return model({"i17": "2", "i52": str(cap), "i53": str(month)}) == "1"

    assert not accepts(strict, 2_499) and accepts(strict, 2_500)
    assert not accepts(average, 2_142) and accepts(average, 2_143)
    assert "must be 2,500" in guide and "2,000 per 30 days is refused" in guide
    assert "2,143 per 30 days is enough" in guide


def test_the_documented_sender_count_fits_and_one_more_does_not():
    assert "29 listed senders" in GUIDE.read_text(encoding="utf-8")
    keys = ["%096x" % n for n in range(1, 31)]
    recipient_policy.receive_rule(senders=keys[:29])
    with pytest.raises(ValueError, match="would not register"):
        recipient_policy.receive_rule(senders=keys)


@pytest.mark.parametrize("path", EVERY_DOC, ids=lambda path: path.name)
def test_no_document_describes_the_encoding_this_one_replaced(path):
    """Before the record, the hold rode on i17 itself (1 + N seconds, 10^18 + N
    blocks) and a refusal was RECIPIENT_MAX_HOLD."""
    text = path.read_text(encoding="utf-8")
    for stale in ("RECIPIENT_MAX_HOLD", "1000000000000000000", "10^18", "receive stream `i17`",
                  "receive stream (`i17`)"):
        assert stale not in text, stale
