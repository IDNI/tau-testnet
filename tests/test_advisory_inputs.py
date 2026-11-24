"""The advisory evaluator feeds input VALUES, not in-spec literals.

No engine needed: this is the shape of what is handed to the worker session.
"""
import tau_advisory


def test_a_wrapped_bv_literal_is_fed_bare():
    """`{ #x.. }:bv[384]` is how the in-process shrink layer wants a pubkey; the
    engine refuses it as an input value, and the consensus answer came back with
    no o6/o7."""
    named = tau_advisory.AdvisoryEvaluator._named({13: "{ #x0a1b }:bv[384]"})
    assert named == {"i13": "#x0a1b"}


def test_bare_values_and_stream_names_pass_through():
    named = tau_advisory.AdvisoryEvaluator._named({"i10": "1", 14: 200000, "15": "0"})
    assert named == {"i10": "1", "i14": "200000", "i15": "0"}


REFUSED = {"ok": False, "outputs": None, "diagnostics": "(Error) refused"}


class _FakeSession:
    def __init__(self, reply):
        self.reply = reply
        self.killed = False

    def step(self, inputs):
        return self.reply

    def kill(self):
        self.killed = True


def _evaluator_with(reply, monkeypatch):
    ev = tau_advisory.AdvisoryEvaluator()
    session = _FakeSession(reply)

    def ensure(*_args):
        ev._session = session
        return session

    monkeypatch.setattr(ev, "_ensure_consensus", ensure)
    monkeypatch.setattr(ev, "_ensure", ensure)
    return ev, session


def test_failed_consensus_step_gives_none(monkeypatch):
    """A dict of None values reads as a verdict of 0, so a refused step must
    give no answer at all."""
    ev, _ = _evaluator_with(REFUSED, monkeypatch)
    assert ev.evaluate_consensus("rules", {}, (6, 7)) is None


def test_failed_many_step_gives_none(monkeypatch):
    ev, _ = _evaluator_with(REFUSED, monkeypatch)
    assert ev.evaluate_many("spec", {}, (6, 7)) is None


def test_ok_step_without_outputs_gives_none(monkeypatch):
    ev, _ = _evaluator_with({"ok": True, "outputs": None}, monkeypatch)
    assert ev.evaluate_consensus("rules", {}, (6, 7)) is None
    assert ev.evaluate_many("spec", {}, (6, 7)) is None


def test_ok_step_gives_outputs(monkeypatch):
    ev, _ = _evaluator_with({"ok": True, "outputs": {"o6": "1", "o7": "1"}}, monkeypatch)
    assert ev.evaluate_consensus("rules", {}, (6, 7)) == {6: "1", 7: "1"}
    assert ev.evaluate_many("spec", {}, (6, 7)) == {6: "1", 7: "1"}


def test_failed_step_keeps_session(monkeypatch):
    """A refused step advances nothing and the worker stays healthy."""
    ev, session = _evaluator_with(REFUSED, monkeypatch)
    ev.evaluate_consensus("rules", {}, (6, 7))
    ev.evaluate_many("spec", {}, (6, 7))
    assert ev._session is session
    assert session.killed is False
