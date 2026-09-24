"""Consensus rules may not read a previous step, and that is enforced.

Header verification runs on an evaluator reconstructed from rules alone -- it is
isolated because stepping the authoritative one for a header that may be verified
twice, rejected, or never become a block corrupts the history every later
transaction reads. That isolated evaluator cannot reproduce input history, so a
consensus rule that reads a previous step would be unverifiable.

A source comment saying "revisit this" would not stop one from arriving.
"""
import pytest


def test_a_temporal_consensus_revision_is_refused_at_admission():
    """An enforceable boundary, not a note to revisit.

    Header verification runs on an evaluator reconstructed from rules alone, so
    it cannot reproduce the input history a `[t-k]` consensus rule would read.
    Nothing may introduce one while that is true.
    """
    from consensus.admission import _temporal_backreference

    # the boundary means "any reference to something other than the current step",
    # not "any text matching one spelling of t-N"
    assert _temporal_backreference(["always ( o6[t]:bv[16] = i10[t-1]:bv[16] )."])
    assert _temporal_backreference(["always ( o6[t]:bv[16] = i10[t - 1]:bv[16] )."])
    assert _temporal_backreference(["always ( o6[t]:bv[16] = i10[ t  -  2 ]:bv[16] )."])
    assert _temporal_backreference(["always ( o7[t]:bv[16] = o7[t-2]:bv[16] )."])
    assert _temporal_backreference(["always ( o6[t]:bv[16] = i10[3]:bv[16] )."])
    # a stream name the scanner cannot resolve fails closed
    assert _temporal_backreference(["always ( o6[t]:bv[16] = i10 )."])
    # current-step references are fine
    assert _temporal_backreference(["always ( o6[t]:bv[16] = { #x0001 }:bv[16] )."]) is None
    assert _temporal_backreference(["always ( o6[ t ]:bv[16] = i10[t]:bv[16] )."]) is None
    # a comment mentioning one is not one
    assert _temporal_backreference(["# i10[t-1] was considered\nalways ( o6[t]:bv[16] = { #x0001 }:bv[16] )."]) is None
