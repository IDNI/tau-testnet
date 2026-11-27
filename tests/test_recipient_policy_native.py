"""The recipient-side rules against the real engine.

Every other test of the feature answers from the Python models in
`recipient_rules`. This file holds the models to the engine: for each documented
rule and every record on the grid, the engine's verdict must be the model's.
"""
import hashlib
import itertools
import os

import pytest

import tau_defs
import tau_policy
from consensus import recipient_policy, sender_policy

import recipient_rules as rules


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIMEOUT = 120.0
NEVER = tau_defs.RECEIVE_NEVER
SECONDS, BLOCKS = recipient_policy.SECONDS, recipient_policy.BLOCKS
Record = recipient_policy.ReceiveRecord
DAY, WEEK = 86_400, 604_800


def _key(label: str) -> str:
    digits = "".join(hashlib.sha256((label + s).encode()).hexdigest() for s in ("", "x", "y"))[:96]
    assert not digits.isdigit()
    return digits


A, B, C = _key("payer"), _key("owner"), _key("shop")

EVERYTHING = (A, 30 * DAY, 3_600, 500, WEEK, 90 * DAY)
RULES = [
    ("allow-list", rules.allow_list(A), rules.allow_list_model(A)),
    ("allow-list of two", rules.allow_list(A, C), rules.allow_list_model(A, C)),
    ("instant and final only", rules.final_only(), rules.final_only_model()),
    ("held 600 s at most", rules.max_hold(600), rules.max_hold_model(600)),
    ("one unit", rules.one_unit(C, A, 600), rules.one_unit_model(C, A, 600)),
    ("held 600 s or 100 blocks at most", rules.max_hold_either(600, 100),
     rules.max_hold_either_model(600, 100)),
    ("no timed park, 5 blocks at most", rules.max_hold_either(0, 5),
     rules.max_hold_either_model(0, 5)),
    ("held 30 days, taken back within 1 hour", rules.hold_and_recall(30 * DAY, 3_600),
     rules.hold_and_recall_model(30 * DAY, 3_600)),
    ("hold plus recall window 1 hour", rules.hold_plus_recall(3_600),
     rules.hold_plus_recall_model(3_600)),
    ("at least 500 a week or no limit", rules.min_allowance(500, WEEK),
     rules.min_allowance_model(500, WEEK)),
    ("on average 500 a 30 days", rules.average_allowance(500, 30 * DAY),
     rules.average_allowance_model(500, 30 * DAY)),
    ("no limits", rules.no_limits(), rules.no_limits_model()),
    ("nothing refunded within 90 days", rules.min_refund(90 * DAY),
     rules.min_refund_model(90 * DAY)),
    ("no refunds", rules.no_refunds(), rules.no_refunds_model()),
    ("every condition in one rule", rules.combined(*EVERYTHING),
     rules.combined_model(*EVERYTHING)),
]

# Every record the node feeds for a transfer or a park, at each bound of the
# rules above and one beside it ...
FED = [recipient_policy.FINAL] + [
    recipient_policy.park_record(SECONDS, n)
    for n in (1, 2, 600, 601, 1_800, 1_801, 3_600, 3_601, 30 * DAY, 30 * DAY + 1, 90 * DAY)
] + [
    recipient_policy.park_record(BLOCKS, n) for n in (1, 5, 6, 100, 101, 100_000)
]
# ... and records with the other conditions, as a payment with a spending limit
# or a refund would carry them. Limits stay inside the record's ceilings.
_TIMED = Record(kind=tau_defs.RECEIVE_KIND_SECONDS)
TERMS = [
    Record(kind=tau_defs.RECEIVE_KIND_OWN),
    _TIMED,
    _TIMED._replace(hold=30 * DAY, recall=3_600),
    _TIMED._replace(hold=30 * DAY + 1),
    _TIMED._replace(recall=3_601),
    _TIMED._replace(hold=1_800, recall=1_800),
    _TIMED._replace(hold=1_800, recall=1_801),
    _TIMED._replace(hold=NEVER, recall=NEVER),
    Record(kind=tau_defs.RECEIVE_KIND_BLOCKS, limit=5_000, period=1_000, refund=NEVER),
    Record(kind=4), Record(kind=NEVER),
] + [
    _TIMED._replace(limit=limit, period=period)
    for limit, period in (
        (0, 1), (499, WEEK), (500, WEEK), (500, WEEK + 1), (999, WEEK + 1),
        (1_000, WEEK + 1), (150, 7 * DAY), (2_499, 30 * DAY), (2_500, 30 * DAY),
        (2_143, 30 * DAY), (2_142, 30 * DAY), (26_499, 31_622_400), (26_500, 31_622_400),
        (16_777_215, 31_622_400), (16_777_215, 1),
    )
] + [
    _TIMED._replace(refund=refund) for refund in (0, 90 * DAY - 1, 90 * DAY, NEVER - 1)
] + [
    Record(kind=2, hold=30 * DAY, recall=3_600, limit=2_500, period=30 * DAY, refund=90 * DAY),
    Record(kind=2, hold=30 * DAY, recall=3_600, limit=2_499, period=30 * DAY, refund=90 * DAY),
    Record(kind=2, hold=30 * DAY, recall=3_600, limit=2_500, period=30 * DAY,
           refund=90 * DAY - 1),
]
RECORDS = [None] + FED + TERMS


@pytest.fixture(scope="module")
def evaluator():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=env, timeout=TIMEOUT)
    yield ev
    ev.close()


def _transfer(sender, recipient, amount=25):
    return {
        1: str(amount), 2: "1000",
        3: "{ #x" + sender + " }:bv[384]",
        4: "{ #x" + recipient + " }:bv[384]",
        12: "{ #x" + sender + " }:bv[384]",
        5: "1700000000",
    }


def _inputs(sender, recipient, record):
    values = _transfer(sender, recipient)
    if record is not None:
        values = recipient_policy.receive_inputs(values, record)
    return sender_policy.clause_inputs(values)


def test_the_grid_stays_inside_the_ceilings_of_the_record():
    """Above them a payment is refused before the receiver's rule is asked, so
    the rules are held to the engine where they can be asked."""
    for record in FED + TERMS:
        assert recipient_policy.record_ceiling_error(record) is None, record


@pytest.mark.parametrize("name, body, model", RULES, ids=[r[0] for r in RULES])
def test_the_engine_decides_what_the_model_decides(evaluator, name, body, model):
    assert evaluator.validate(body).ok, name
    for record, (sender, recipient) in itertools.product(
            RECORDS, [(A, B), (C, B), (B, C)]):
        inputs = _inputs(sender, recipient, record)
        verdict = evaluator.verdict(body, inputs)
        assert verdict.blocked is (model(inputs) == "0"), (name, record, sender[:6], recipient[:6])


def test_the_two_readings_of_a_limit_differ_where_the_design_says(evaluator):
    """150 a week against 500 a month: refused by the strict reading (it stops
    a receiver who spends 500 in one week), accepted by the average."""
    weekly_150 = Record(kind=2, limit=150, period=7 * DAY)
    strict, average = rules.min_allowance(500, 30 * DAY), rules.average_allowance(500, 30 * DAY)
    inputs = _inputs(A, B, weekly_150)
    assert evaluator.verdict(strict, inputs).blocked is True
    assert evaluator.verdict(average, inputs).blocked is False
    # 500 a week meets 500 a month in both
    weekly_500 = _inputs(A, B, weekly_150._replace(limit=500))
    assert evaluator.verdict(strict, weekly_500).blocked is False
    assert evaluator.verdict(average, weekly_500).blocked is False
    # a monthly limit against a weekly minimum: five weeks can touch one month
    weekly = rules.min_allowance(500, WEEK)
    assert evaluator.verdict(
        weekly, _inputs(A, B, Record(kind=2, limit=2_500, period=30 * DAY))).blocked is False
    assert evaluator.verdict(
        weekly, _inputs(A, B, Record(kind=2, limit=2_000, period=30 * DAY))).blocked is True


def test_a_recipient_can_require_a_custom_input_of_the_payer(evaluator):
    """The payer's custom inputs reach the recipient's clause; an input the
    payer did not send reads 0."""
    body, model = rules.needs_reference(30), rules.needs_reference_model(30)
    assert evaluator.validate(body).ok
    park = recipient_policy.park_record(SECONDS, 600)
    for record, reference in itertools.product(
            [None, recipient_policy.FINAL, park], [None, "0", "4711"]):
        values = _transfer(A, B)
        if reference is not None:
            values[30] = reference
        if record is not None:
            values = recipient_policy.receive_inputs(values, record)
        inputs = sender_policy.clause_inputs(values)
        assert evaluator.verdict(body, inputs).blocked is (model(inputs) == "0"), (record, reference)


def test_the_documented_rules_share_one_worker_without_a_width_conflict(evaluator):
    """All of them type the record's inputs at bv[64], which is what the width
    screen enforces."""
    park = recipient_policy.park_record(SECONDS, 600)
    for _name, body, model in RULES * 2:
        inputs = _inputs(A, B, park)
        assert evaluator.verdict(body, inputs).blocked is (model(inputs) == "0")
    widths = evaluator.stats()["widths"]
    for index in tau_defs.RECEIVE_RECORD_INDICES:
        assert widths["i%d" % index] == tau_defs.RECEIVE_STREAM_BV_WIDTH


def test_an_unfed_record_reads_as_the_owners_own_payment(evaluator):
    """The sender pass does not feed the record. The worker's default for an
    unfed input is 0, and kind 0 is the owner's own payment, so the receive
    part of a rule never fires for what its owner sends."""
    body = rules.allow_list(A)
    assert evaluator.verdict(body, _inputs(C, B, None)).blocked is False
    assert evaluator.verdict(body, _inputs(C, B, recipient_policy.FINAL)).blocked is True
    for _name, rule, _model in RULES:
        if "one unit" in _name:
            continue                      # restricts what its owner sends, too
        assert evaluator.verdict(rule, _inputs(B, C, None)).blocked is False, _name


def _asks(evaluator, body):
    def allows(record):
        return not evaluator.verdict(body, _inputs(A, B, record)).blocked
    return allows


def test_the_refused_condition_is_found_on_the_engine(evaluator):
    body = rules.combined(*EVERYTHING)
    allows = _asks(evaluator, body)
    fine = Record(kind=2, hold=30 * DAY, recall=3_600, limit=2_500, period=30 * DAY,
                  refund=90 * DAY)
    assert allows(fine)
    for change, condition in (
        (dict(hold=30 * DAY + 1), recipient_policy.HOLD),
        (dict(recall=3_601), recipient_policy.RECALL),
        (dict(limit=2_499), recipient_policy.LIMIT),
        (dict(refund=90 * DAY - 1), recipient_policy.REFUND),
        (dict(hold=30 * DAY + 1, refund=0), recipient_policy.HOLD),
        (dict(recall=3_601, limit=1), recipient_policy.RECALL),
    ):
        record = fine._replace(**change)
        assert not allows(record)
        assert recipient_policy.refused_condition(allows, record) == condition, change

    stranger = lambda record: not evaluator.verdict(body, _inputs(C, B, record)).blocked
    assert recipient_policy.refused_condition(stranger, fine) == recipient_policy.SENDER

    tied = _asks(evaluator, rules.hold_plus_recall(3_600))
    park = recipient_policy.park_record(SECONDS, 2_400)
    assert not tied(park)
    assert recipient_policy.refused_condition(tied, park) == recipient_policy.COMBINED


def test_the_longest_accepted_hold_and_recall_window_are_found_on_the_engine(evaluator):
    allows = _asks(evaluator, rules.hold_and_recall(30 * DAY, 3_600))
    find = recipient_policy.longest_accepted
    assert find(allows, SECONDS, recipient_policy.HOLD, None, 7_776_000) == 30 * DAY
    assert find(allows, SECONDS, recipient_policy.RECALL, 7_200, 7_776_000) == 3_600
    assert find(allows, BLOCKS, recipient_policy.HOLD, None, 100_000) is None

    park = recipient_policy.park_record(BLOCKS, 30)
    assert recipient_policy.accepted_instead(
        _asks(evaluator, rules.max_hold(600)), park, recipient_policy.HOLD,
        seconds_window=7_776_000, blocks_window=100_000,
    ) == {"max_hold_blocks": 0, "max_hold_seconds": 600}


def test_the_farthest_accepted_height_release_is_found_on_the_engine(evaluator):
    allows = _asks(evaluator, rules.max_hold_either(600, 100))

    def bounds(record):
        return recipient_policy.accepted_instead(
            allows, record, recipient_policy.HOLD,
            seconds_window=7_776_000, blocks_window=100_000)

    assert bounds(recipient_policy.park_record(BLOCKS, 101)) == {"max_hold_blocks": 100}
    assert bounds(recipient_policy.park_record(BLOCKS, 100_000)) == {"max_hold_blocks": 100}
    assert bounds(recipient_policy.park_record(SECONDS, 3_600)) == {"max_hold_seconds": 600}
    assert recipient_policy.longest_accepted(
        allows, BLOCKS, recipient_policy.HOLD, None, 100_000) == 100


# --- rules written from numbers --------------------------------------------------

import test_receive_rule_writer as writer  # noqa: E402

_HEIGHT = Record(kind=tau_defs.RECEIVE_KIND_BLOCKS)
WRITTEN_RECORDS = RECORDS + [
    _HEIGHT, _HEIGHT._replace(hold=50, recall=5), _HEIGHT._replace(hold=50, recall=6),
    _HEIGHT._replace(hold=51, recall=5), _HEIGHT._replace(hold=1_000, recall=10),
    _HEIGHT._replace(hold=1_001, recall=10),
    _HEIGHT._replace(limit=3_999, period=400_000), _HEIGHT._replace(limit=4_000, period=400_000),
    _HEIGHT._replace(limit=500, period=50_000), _HEIGHT._replace(limit=499, period=50_000),
    _HEIGHT._replace(refund=999), _HEIGHT._replace(refund=1_000),
    _HEIGHT._replace(refund=200_000), _HEIGHT._replace(refund=199_999),
    _HEIGHT._replace(hold=1_000, recall=10, limit=4_000, period=400_000, refund=200_000),
    _TIMED._replace(limit=16_777_215, period=31_622_400, hold=1),
    _TIMED._replace(limit=16_777_214, period=1, hold=1),
    _TIMED._replace(refund=NEVER, hold=600),
]


@pytest.mark.parametrize("numbers", writer.ALL_NUMBERS)
def test_a_written_rule_decides_what_its_numbers_say(evaluator, numbers):
    """Every rule the writer produces, on the engine, against a model written
    from the meaning of the numbers."""
    body = recipient_policy.receive_rule(**numbers)
    from consensus.rule_offers import clause_body_v1

    body = clause_body_v1(body)
    model = rules.written_model(**numbers)
    assert evaluator.validate(body).ok
    for record, sender in itertools.product(WRITTEN_RECORDS, [writer.ALICE, writer.BOB, C]):
        assert record is None or recipient_policy.record_ceiling_error(record) is None
        inputs = _inputs(sender, B, record)
        verdict = evaluator.verdict(body, inputs)
        assert verdict.blocked is (model(inputs) == "0"), (numbers, record, sender[:6])
