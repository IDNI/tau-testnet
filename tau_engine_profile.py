"""Pins the native engine to the configuration the node is tested with.

`prepare_environment` strips engine inputs before `import tau`; `apply` forces
and verifies the tested option values after it, raising `EngineProfileError`.
"""
import hashlib
import json
import logging
import os
import sys

logger = logging.getLogger(__name__)


class EngineProfileError(RuntimeError):
    """The engine does not match the tested profile.

    Not an ImportError, so callers that treat ImportError as "engine absent"
    cannot fall back around it.
    """


MANIFEST = {
    "ba-complement": "program",
    "ba-component-factoring": "true",
    "ba-decision-pins": "4096",
    "bf-dependence-max-nodes": "65536",
    "block-max-rounds": "0",
    "block-max-splits": "0",
    "block-squeeze-cap": "0",
    "bv-bitblast-max-nodes": "1048576",
    "bv-bitblast-max-width": "16",
    "bv-bitblast-qf-max-nodes": "16384",
    "bv-blastdepth": "0",
    "bv-blasting": "true",
    "bv-blasting-max-nodes": "500000",
    "bv-case-split": "true",
    "bv-case-split-max-growth": "16",
    "bv-case-split-max-tests": "0",
    "bv-defelim-max-atoms": "18",
    "bv-defelim-max-clauses": "16",
    "bv-defelim-max-rounds": "256",
    "bv-defelim-max-subset": "4",
    "bv-definitional-elimination": "true",
    "bv-max-width": "1024",
    "bv-quantifier-free-decision": "true",
    "bv-solve-timeout": "60",
    "bv-widening": "false",
    "cache-bound": "4096",
    "compile-build-timeout": "3600",
    "compile-max-table-edges": "400",
    "cqe-max-clauses": "0",
    "gc-growth-factor": "1.5",
    "gc-min-size": "256",
    "hsb-max-dimension": "4096",
    "hsb-max-dnf-clauses": "1048576",
    "lean-decide-crosscheck": "false",
    "lgrs-max-vars": "8",
    "log-max-nodes": "10000",
    "ltl-alg": "auto",
    "ltl-closed-regions-timeout": "20",
    "ltl-compositional": "false",
    "ltl-ctl-star-tableau-max-states": "64",
    "ltl-data-fixpoint-rounds": "64",
    "ltl-data-game-max-combinations": "4096",
    "ltl-data-game-max-memo": "33554432",
    "ltl-data-game-max-nodes": "8388608",
    "ltl-decompose": "",
    "ltl-export-strategy": "",
    "ltl-export-strategy-file": "",
    "ltl-fixed-step-split-max-bits": "2",
    "ltl-guard-max-cubes": "512",
    "ltl-hoa-max-states": "4194304",
    "ltl-max-game-aps": "30",
    "ltl-max-observations": "8",
    "ltl-mealy-max-edges": "65536",
    "ltl-mealy-max-states": "4096",
    "ltl-minimize-strategy": "false",
    "ltl-parameters": "existential",
    "ltl-propositions": "hybrid",
    "ltl-qe-max-vars": "2",
    "ltl-refinement-rounds": "64",
    "ltl-self-check-steps": "64",
    "ltl-semantics": "infinite",
    "ltl-simplification": "",
    "ltl-strategy-max-states": "0",
    "ltl-synth-algo": "",
    "ltl-timeout": "60",
    "ltl-window-max-paths": "4096",
    "ltl-witness": "false",
    "max-consistency-subsets": "4096",
    "max-constant-size": "2000",
    "max-cover-products": "256",
    "max-def-passes": "0",
    "max-enum-steps": "0",
    "max-fixpoint-steps": "500",
    "max-flag-search-steps": "500",
    "max-probe-steps": "10000",
    "max-revision-alts": "0",
    "max-rewrite-rounds": "0",
    "max-simplify-rounds": "0",
    "nlang-api-key": "unset",
    "nlang-effort": "",
    "nlang-endpoint": "",
    "nlang-fallback": "true",
    "nlang-http-timeout": "15",
    "nlang-max-tokens": "16000",
    "nlang-model": "",
    "nlang-provider": "",
    "output-prefer": "",
    "phi-delta-crosscheck": "false",
    "preprocessing": "false",
    "pwr-semantic": "false",
    "qlt-cells-budget": "65536",
    "qlt-cells-max-params": "2",
    "qlt-const-output-max": "100",
    "qlt-t3-cap": "20",
    "spec-size-warn": "0",
    "spot-bin": "",
    "step-definitional-propagation": "true",
    "tref-budget": "0",
    "tref-budget-soft": "75",
}

# Written as "" to clear the key; the engine reads it back masked.
_SET_TEXT = {"nlang-api-key": ""}

_OPTION_ENV_PREFIX = "TAU_"
_EXTRA_ENGINE_VARS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY")
_EXTERNAL_TOOLS = ("ltlsynt", "autfilt", "ltlfilt")
# Searched by the OS when PATH is unset.
_DEFAULT_SEARCH_DIRS = ("/usr/bin", "/bin")

_digest_logged = False


def manifest_digest(manifest=None):
    canonical = json.dumps(MANIFEST if manifest is None else manifest,
                           sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def option_env_name(option):
    return _OPTION_ENV_PREFIX + option.replace("-", "_").upper()


def _dir_has_tool(directory):
    base = directory or "."
    return any(os.path.exists(os.path.join(base, tool))
               for tool in _EXTERNAL_TOOLS)


def scrub_path(path_value, has_tool=_dir_has_tool):
    """Returns (kept PATH text, dropped entries), preserving order."""
    kept, dropped = [], []
    for entry in path_value.split(os.pathsep):
        (dropped if has_tool(entry) else kept).append(entry)
    return os.pathsep.join(kept), dropped


def prepare_environment(environ=os.environ):
    """Removes engine inputs from `environ`; returns the dropped PATH entries."""
    for option in MANIFEST:
        name = option_env_name(option)
        if name in environ:
            logger.info("Ignoring engine option variable %s", name)
            del environ[name]
    for name in _EXTRA_ENGINE_VARS:
        environ.pop(name, None)

    dropped = []
    path_value = environ.get("PATH")
    if path_value:
        kept, dropped = scrub_path(path_value)
        for entry in dropped:
            logger.warning("Dropping PATH entry %r", entry)
        if dropped:
            if kept:
                environ["PATH"] = kept
            else:
                del environ["PATH"]
    return dropped


def _package_spot_dirs():
    """Directories the engine searches relative to the running executable."""
    executables = {sys.executable, os.path.realpath(sys.executable),
                   getattr(sys, "_base_executable", None) or sys.executable}
    dirs = []
    for exe in sorted(executables):
        exe_dir = os.path.dirname(exe)
        for candidate in (
            os.path.normpath(os.path.join(exe_dir, "..", "libexec", "tau", "spot")),
            os.path.join(exe_dir, "libexec", "tau", "spot"),
        ):
            if candidate not in dirs:
                dirs.append(candidate)
    return dirs


def _unscrubbable_locations(environ):
    found = [d for d in _package_spot_dirs() if _dir_has_tool(d)]
    path_value = environ.get("PATH")
    if path_value is None:
        found += [d for d in _DEFAULT_SEARCH_DIRS if _dir_has_tool(d)]
    else:
        found += [e for e in path_value.split(os.pathsep) if _dir_has_tool(e)]
    return found


def apply(tau_module, environ=os.environ):
    """Forces and verifies the manifest on a freshly imported engine."""
    global _digest_logged
    names = set(tau_module.option_names())
    expected = set(MANIFEST)
    if names != expected:
        raise EngineProfileError(
            "engine options differ from the tested profile: "
            f"extra={sorted(names - expected)} missing={sorted(expected - names)}")

    for option, value in MANIFEST.items():
        tau_module.set_option(option, _SET_TEXT.get(option, value))
    mismatched = []
    for option, value in MANIFEST.items():
        actual = tau_module.get_option(option).value
        if actual != value:
            mismatched.append(f"{option}={actual!r} (expected {value!r})")
    if mismatched:
        raise EngineProfileError(
            "engine options differ from the tested profile: " + "; ".join(mismatched))

    locations = _unscrubbable_locations(environ)
    if locations:
        raise EngineProfileError(
            f"engine search locations hold unexpected tools: {locations}")

    if not _digest_logged:
        _digest_logged = True
        logger.info("Engine profile pinned (manifest sha256 %s)", manifest_digest())
