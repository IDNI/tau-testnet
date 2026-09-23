"""A production node must log its authority lifecycle at INFO.

Logger names are dot-hierarchical, so the "tau" entry never covered
"tau_authority": a node logged none of its genesis commit, reconstruction, loans
or promotion below WARNING, and the e2e run had nothing to read.
"""
import logging

import pytest

import config
import tau_logging

AUTHORITY_STACK = [
    "consensus.engine",
    "tau_admission",
    "tau_advisory",
    "tau_allocator",
    "tau_authority",
    "tau_commit",
    "tau_journal",
    "tau_proposal",
    "tau_reconstruction",
    "tau_session",
]


@pytest.fixture
def info_logging():
    tau_logging.configure({"level": "INFO"}, force=True)
    try:
        yield
    finally:
        tau_logging.configure(config.LOGGING, force=True)


@pytest.mark.parametrize("name", AUTHORITY_STACK)
def test_the_authority_stack_logs_at_info(info_logging, name):
    assert logging.getLogger(name).isEnabledFor(logging.INFO), (
        f"{name} is silenced below WARNING at level INFO")


def test_third_party_noise_stays_quiet(info_logging):
    assert not logging.getLogger("libp2p").isEnabledFor(logging.INFO)
