"""
README ↔ source consistency checker.

Guards the launch README against drift: every environment variable, CLI command,
file path, ``gen_genesis.py`` flag, and error code it names must actually exist
in the codebase. This is intentionally source-text based (no fragile imports) so
it keeps working as modules move around — it only asks "is this name real?".

Run: ``./venv/bin/python3 -m pytest -p no:asyncio tests/test_readme_consistency.py``
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
README = (REPO / "README.md").read_text(encoding="utf-8")

# Source trees scanned for "is this token real?" checks. Docs are excluded so a
# typo copied between two docs cannot vouch for itself.
_SCAN_EXTS = {".py", ".sh", ".yml", ".yaml", ".toml", ".cfg"}
_SCAN_EXTRA_NAMES = {"Dockerfile", "Dockerfile.standalone"}
_SKIP_DIRS = {".git", "venv", ".venv", "data", "node_modules", "__pycache__",
              "build-Release", "docs", ".claude"}


def _iter_source_files():
    for p in REPO.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(REPO).parts):
            continue
        if p.suffix in _SCAN_EXTS or p.name in _SCAN_EXTRA_NAMES or p.name.startswith("Dockerfile"):
            yield p


_SOURCE_BLOB = None


def _source_blob():
    global _SOURCE_BLOB
    if _SOURCE_BLOB is None:
        chunks = []
        for p in _iter_source_files():
            try:
                chunks.append(p.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                pass
        _SOURCE_BLOB = "\n".join(chunks)
    return _SOURCE_BLOB


def _readme_code_blocks():
    """Yield the contents of fenced code blocks (where examples live)."""
    return re.findall(r"```[a-zA-Z]*\n(.*?)```", README, flags=re.DOTALL)


# --------------------------------------------------------------------------- #

def test_env_vars_named_in_readme_exist_in_source():
    """Every TAU_* env var in the README must appear somewhere in the source
    (code, Dockerfiles, scripts, compose) — catches typos and removed vars."""
    # TAU_*-shaped tokens that are NOT config env vars: the domain-separation
    # examples in the cryptography section (a proposed signature prefix format).
    NON_ENV = {"TAU_TESTNET_TX_V1", "TAU_TESTNET_BLOCK_V1"}
    readme_vars = set(re.findall(r"\bTAU_[A-Z0-9_]+\b", README)) - NON_ENV
    assert readme_vars, "expected to find TAU_* vars in the README"

    blob = _source_blob()
    known = set(re.findall(r"\bTAU_[A-Z0-9_]+\b", blob))

    unknown = sorted(readme_vars - known)
    assert not unknown, (
        "README names TAU_* env vars not found anywhere in source "
        f"(typo or removed?): {unknown}"
    )


def test_cli_commands_in_readme_exist():
    """Every `tau-testnet <cmd>`/`<cmd> <sub>` invocation must map to a real
    argparse subcommand in tau_testnet_cli/cli.py."""
    cli_src = (REPO / "tau_testnet_cli" / "cli.py").read_text(encoding="utf-8")
    known_cmds = set(re.findall(r"""add_parser\(\s*["']([a-z][a-z0-9_-]*)["']""", cli_src))
    assert known_cmds, "could not extract any CLI subcommands from cli.py"

    # Tokens that follow `tau-testnet` in README examples but are not commands.
    GLOBAL_FLAGS_WITH_ARG = {"--host", "--port"}

    referenced = set()
    for block in _readme_code_blocks():
        for line in block.splitlines():
            line = line.strip()
            if "tau-testnet " not in line:
                continue
            # take the segment after the FIRST `tau-testnet`
            seg = line.split("tau-testnet ", 1)[1]
            toks = seg.split()
            # skip leading global flags (and their values) like --host X --port Y
            i = 0
            picked = []
            while i < len(toks) and len(picked) < 2:
                t = toks[i]
                if t in GLOBAL_FLAGS_WITH_ARG:
                    i += 2
                    continue
                if t.startswith("-"):
                    i += 1
                    continue
                if re.fullmatch(r"[a-z][a-z0-9_-]*", t):
                    picked.append(t)
                    i += 1
                else:
                    break
            referenced.update(picked)

    unknown = sorted(referenced - known_cmds)
    assert not unknown, (
        f"README uses `tau-testnet` commands not defined in cli.py: {unknown}. "
        f"Known: {sorted(known_cmds)}"
    )


def test_repo_paths_in_readme_exist():
    """File/dir paths the README points at must exist in the repo."""
    candidates = set(re.findall(
        r"`([A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:py|tau|json|yml|yaml|md|toml|sh))`",
        README,
    ))
    # Directory references in backticks (e.g. `web-wallet/`, `consensus/`).
    candidates |= set(re.findall(r"`([a-z][a-z0-9_]*/)`", README))

    # Placeholders / generated artifacts that are not expected to exist in the
    # checkout (created at runtime or supplied by an operator).
    IGNORE = {
        "data/genesis.json", "node.db", "consensus_update.json",
        "data/identity.key", "data/peerstore", "data/test_miner.key",
    }
    # Accept either a full repo-relative path or a bare basename (prose may say
    # `gen_genesis.py` where the file lives at `scripts/gen_genesis.py`).
    basenames = {
        p.name for p in REPO.rglob("*")
        if p.is_file() and not any(part in _SKIP_DIRS for part in p.relative_to(REPO).parts)
    }
    missing = sorted(
        c for c in candidates
        if c not in IGNORE
        and not (REPO / c).exists()
        and Path(c).name not in basenames
    )
    assert not missing, f"README references repo paths that do not exist: {missing}"


def test_gen_genesis_flags_in_readme_exist():
    """Flags shown in the README's gen_genesis.py example must be real."""
    gg_src = (REPO / "scripts" / "gen_genesis.py").read_text(encoding="utf-8")
    known_flags = set(re.findall(r"""add_argument\(\s*["'](--[a-z][a-z0-9-]*)["']""", gg_src))
    assert known_flags, "could not extract gen_genesis flags"

    # Pull flags from any README code block that invokes gen_genesis.py.
    used = set()
    for block in _readme_code_blocks():
        if "gen_genesis.py" not in block:
            continue
        used.update(re.findall(r"(--[a-z][a-z0-9-]*)", block))

    unknown = sorted(used - known_flags)
    assert not unknown, (
        f"README uses gen_genesis.py flags that do not exist: {unknown}. "
        f"Known: {sorted(known_flags)}"
    )


def test_error_codes_in_readme_exist_in_source():
    """Every error code listed in the README must appear in the source."""
    # The README lists codes as inline-code UPPER_SNAKE tokens in the
    # "Error codes:" paragraph.
    m = re.search(r"Error codes:\s*(.+)", README)
    assert m, "could not find the README error-code list"
    codes = set(re.findall(r"`([A-Z][A-Z0-9_]{3,})`", m.group(1)))
    assert codes, "no error codes parsed from the README"

    blob = _source_blob()
    missing = sorted(c for c in codes if c not in blob)
    assert not missing, f"README lists error codes not found in source: {missing}"
