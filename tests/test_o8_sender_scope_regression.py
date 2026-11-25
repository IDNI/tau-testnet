"""Issue #183: the o8 sender-scope screen is textual, not a proof of gating.

The README says it plainly: o8 fee rules "accumulate in one shared
specification" and the ``UNSCOPED_USER_RULE`` screen "is not proof the rule
is genuinely gated by it". ``_streams_referenced`` only checks that the
tokens ``i12`` / ``i3`` appear somewhere in the rule text (word-boundary,
after stripping comments). It never checks that they *guard* the charged
``o8`` write.

Two reachable forms pass admission today that levy a fee on senders other
than the author's. Both are pinned here as the DESIRED behaviour: on
unfixed main these tests FAIL (the rule is admitted); after a fix that
requires a genuine gate they PASS. The positive control (a real guard)
passes on both.

Scope: the admission screen only. These are pure-Python, no native
interpreter. The block-apply path calls the same ``screen_user_rule_text``,
so the regression holds there too.
"""
from consensus.admission import screen_user_rule_text

PK = "ab" * 48
_LIT = "{ #x" + PK + " }:bv[384]"
_FEE = "{ #x000003 }:bv[24]"
_ZERO = "{ #x000000 }:bv[24]"


def _rejected(rule):
    return screen_user_rule_text(rule, "", False) is not None


def test_positive_control_real_i12_guard_is_admitted():
    """A genuine guard (i12 in a real comparison) is admitted today and must
    stay admitted -- the fix must not over-broaden."""
    rule = "always ((i12[t]:bv[384] = " + _LIT + ") -> o8[t]:bv[24] = " + _FEE + ")."
    assert not _rejected(rule)


def test_tautology_guard_that_mentions_i12_is_rejected():
    """``i12 = i12`` is true for every sender, so both branches charge. The
    screen admits it because ``i12`` merely appears. BUG (desired: rejected)."""
    rule = ("always ( (i12[t]:bv[384] = i12[t]:bv[384]) ? "
            "o8[t]:bv[24] = " + _FEE + " : "
            "o8[t]:bv[24] = " + _FEE + " ).")
    assert _rejected(rule)


def test_i12_in_a_dead_branch_that_gates_only_the_free_side_is_rejected():
    """The author pays zero; every other sender (the ``:`` branch) pays. The
    charged branch is ungated, yet the screen admits it because ``i12``
    appears in the (harmless) guard. BUG (desired: rejected)."""
    rule = ("always ( (i12[t]:bv[384] = " + _LIT + ") ? "
            "o8[t]:bv[24] = " + _ZERO + " : "
            "o8[t]:bv[24] = " + _FEE + " ).")
    assert _rejected(rule)


def test_unscoped_flat_fee_is_rejected_positive_control():
    """The already-pinned case (test_launch_hardening.TestUserRuleSenderScope):
    no i12/i3 at all. Must stay rejected."""
    rule = "always (o8[t]:bv[24] = " + _FEE + ")."
    assert _rejected(rule)
