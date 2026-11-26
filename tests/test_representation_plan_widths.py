"""The representation plan carries the declared width of each interned stream."""
import json
from types import SimpleNamespace

import tau_admission
import tau_allocator as alloc
import tau_authority
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr

KEY = "a1" * 48
WIDE = ("always ( i13[t]:bv[384] = { #x" + KEY + " }:bv[384]"
        " -> o5[t]:bv[24] = { #x000001 }:bv[24] ).")
WIDE_256 = ("always ( i13[t]:bv[256] = { #x" + "b2" * 32 + " }:bv[256]"
            " -> o5[t]:bv[24] = { #x000001 }:bv[24] ).")


def _old_json(plan):
    """A plan stored before the plan had declared widths."""
    return json.dumps({"width": plan.width, "interned": sorted(plan.interned),
                       "plain": sorted(plan.plain)}, sort_keys=True)


def _revisions(*rules):
    return [SimpleNamespace(kind=tj.REVISION, rule_text=r) for r in rules]


def test_the_plan_gives_the_declared_width_of_each_interned_stream(temp_database):
    plan = tr.plan_representation(candidate_rules=[WIDE])
    assert 13 in plan.interned
    assert plan.declared_widths() == {13: 384}


def test_two_declared_widths_of_one_stream_give_no_entry():
    plan = tr.RepresentationPlan(width=8, interned=frozenset({13}))
    assert plan.with_declared_widths([WIDE, WIDE_256]).declared_widths() == {}
    assert plan.with_declared_widths(["", WIDE]).declared_widths() == {13: 384}


def test_a_stream_with_two_declared_widths_is_plain(temp_database):
    plan = tr.plan_representation(history_rules=[WIDE], candidate_rules=[WIDE_256])
    assert 13 in plan.plain and 13 not in plan.interned
    assert plan.declared_widths() == {}


def test_the_widths_are_part_of_the_plan_id_and_of_its_json(temp_database):
    plan = tr.plan_representation(candidate_rules=[WIDE])
    without = tr.RepresentationPlan(width=plan.width, interned=plan.interned,
                                    plain=plan.plain)
    assert plan.plan_id != without.plan_id
    again = tr.RepresentationPlan.from_json(plan.to_json())
    assert again == plan and again.plan_id == plan.plan_id


def test_a_plan_stored_without_widths_keeps_its_stored_id():
    stored = tr.RepresentationPlan(width=8, interned=frozenset({13}),
                                   plain=frozenset({14}))
    read = tr.RepresentationPlan.from_json(_old_json(stored))
    assert read.widths is None
    assert read.plan_id == tj.fingerprint({"width": 8, "interned": [13], "plain": [14]})


def test_the_authority_adds_widths_to_a_plan_stored_without_them():
    stored = tr.RepresentationPlan(width=8, interned=frozenset({13}),
                                   plain=frozenset({14}))
    store = SimpleNamespace(latest_block_commit=lambda: {
        "plan_json": _old_json(stored), "plan_id": stored.plan_id})
    journal = SimpleNamespace(entries=lambda: _revisions(WIDE))
    plan = tau_authority.AuthoritativeTauOwner()._committed_plan(store, journal)
    assert (plan.interned, plan.plain) == (stored.interned, stored.plain)
    assert plan.declared_widths() == {13: 384}


def test_admission_adds_widths_to_a_plan_stored_without_them():
    stored = tr.RepresentationPlan(width=8, interned=frozenset({13}))
    anchor = {"plan_json": _old_json(stored), "plan_id": stored.plan_id}
    plan = tau_admission._plan_for(anchor, _revisions(WIDE), ())
    assert plan.interned == stored.interned
    assert plan.declared_widths() == {13: 384}


def test_a_replan_keeps_the_widths_of_the_streams_that_stay_interned():
    plan = tr.RepresentationPlan(width=8, interned=frozenset({12, 13}),
                                 widths=((12, 384), (13, 384)))
    ctx = tp.ProposalContext(
        session=None, journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(alloc.MappingSnapshot(epoch="e0", committed={}),
                                  width=8, label="proposal"),
        plan=plan, rebuild=lambda j, p: None,
    )
    ctx.replan({12})
    assert ctx.plan.declared_widths() == {13: 384}
