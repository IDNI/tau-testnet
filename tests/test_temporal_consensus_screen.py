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
    from consensus.admission import is_temporal_reference_error, revision_fragment_error

    def temporal(text):
        return is_temporal_reference_error(revision_fragment_error([text]))

    # the boundary means "any reference to something other than the current step",
    # not "any text matching one spelling of t-N"
    assert temporal("always ( o6[t]:bv[16] = i10[t-1]:bv[16] ).")
    assert temporal("always ( o6[t]:bv[16] = i10[t - 1]:bv[16] ).")
    assert temporal("always ( o6[t]:bv[16] = i10[ t  -  2 ]:bv[16] ).")
    assert temporal("always ( o7[t]:bv[16] = o7[t-2]:bv[16] ).")
    assert temporal("always ( o6[t]:bv[16] = i10[3]:bv[16] ).")
    # a stream the parser cannot resolve is refused, though not as temporal
    assert revision_fragment_error(["always ( o6[t]:bv[16] = i10 )."])
    # current-step references are fine
    assert revision_fragment_error(["always ( o6[t]:bv[16] = { #x0001 }:bv[16] )."]) is None
    # a comment mentioning one is not one
    assert revision_fragment_error(["# i10[t-1] was considered\nalways ( o6[t]:bv[16] = { #x0001 }:bv[16] )."]) is None
    # padded brackets are not the current step's spelling
    assert revision_fragment_error(["always ( o6[ t ]:bv[16] = i10[t]:bv[16] )."])
