# Packaging and release workflow

This document describes how `tau-testnet` is packaged and released. Two
artifacts are published per release:

1. A Python distribution (`tau_testnet-<version>-py3-none-any.whl` plus an
   sdist) attached to the GitHub Release.
2. A standalone Docker image at
   `ghcr.io/idni/tau-testnet:<version>` (and `:latest` for stable releases).

## Local builds

### Python wheel + sdist

```bash
python -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip build
python -m build
ls dist/
# tau_testnet-0.1.0-py3-none-any.whl
# tau_testnet-0.1.0.tar.gz
```

The build uses `setuptools` (configured in `pyproject.toml`). Top-level
modules (`server.py`, `wallet.py`, `config.py`, …) are listed in
`[tool.setuptools].py-modules` so they remain importable from the wheel
alongside the new `tau_testnet_cli/` package.

### Standalone Docker image

```bash
docker build -f Dockerfile.standalone -t tau-testnet-standalone:latest .
# or via the CLI:
tau-testnet node docker-build --jobs 4
```

Build args:

| Arg | Default | Purpose |
|---|---|---|
| `TAU_LANG_REPO` | `https://github.com/IDNI/tau-lang.git` | tau-lang git remote |
| `TAU_LANG_REF`  | `main` | tau-lang git ref to check out |
| `TAU_BUILD_JOBS`| `4` | parallel make/cmake jobs for cvc5/boost/tau-lang |

The image carries OCI labels (`org.opencontainers.image.title`,
`description`, `source`, `licenses`) so it shows correctly on the GHCR UI.

## Smoke test

`scripts/package_smoke_test.sh` validates the install path end-to-end on a
fresh checkout:

```bash
# Fast path: install + --help + version + key generation (~30s)
bash scripts/package_smoke_test.sh

# Thorough: also runs the standalone Docker build (5-15 min)
SMOKE_DOCKER=1 bash scripts/package_smoke_test.sh
```

The CI runs the fast path on every release; the Docker build is exercised
separately by the release workflow's `docker-build` job.

## Release workflow

`.github/workflows/release.yml` triggers on tag pushes matching `v*`. Two
parallel jobs run after checkout:

| Job | What it does |
|---|---|
| `python-build` | Sets up Python 3.10, installs deps, runs the CLI test suite (six `tests/test_cli_*.py` files), runs `python -m build`, uploads `dist/*` as workflow artifacts, and attaches them to the GitHub Release. |
| `docker-build` | Logs into GHCR with `GITHUB_TOKEN`, computes image tags, and pushes via `docker/build-push-action`. |

### Tag conventions

The workflow distinguishes **stable** tags from **prerelease** tags via the
regex `^v[0-9]+\.[0-9]+\.[0-9]+$`:

| Tag example | Pushed image tags |
|---|---|
| `v0.1.0`     | `ghcr.io/idni/tau-testnet:v0.1.0` and `:latest` |
| `v1.2.3`     | `ghcr.io/idni/tau-testnet:v1.2.3` and `:latest` |
| `v0.2.0-rc1` | `ghcr.io/idni/tau-testnet:v0.2.0-rc1` only (no `:latest`) |
| `v0.2.0-beta` | `ghcr.io/idni/tau-testnet:v0.2.0-beta` only |

This way a `pip install` or `docker pull ghcr.io/idni/tau-testnet:latest`
always lands on the most recent **stable** release; prerelease tags are
opt-in.

### Cutting a release

```bash
# 1. Bump the version in pyproject.toml AND tau_testnet_cli/__init__.py.
#    (Both must match — tau-testnet version reads pyproject metadata at
#    runtime via importlib.metadata, falling back to __version__.)

# 2. Commit, push, and tag.
git commit -am "release: v0.1.0"
git push origin main
git tag v0.1.0
git push origin v0.1.0

# 3. The release workflow runs automatically. When it finishes:
#    - Wheel + sdist are attached to the GitHub Release.
#    - ghcr.io/idni/tau-testnet:v0.1.0 and :latest are published.
```

For prereleases, use `vX.Y.Z-rcN` / `vX.Y.Z-betaN` etc. The workflow runs
the same way; only `:latest` is held back.

### Manual release (workflow_dispatch)

The workflow also accepts `workflow_dispatch` with a `tag` input, useful
for re-running a failed publish without retagging the repo.

## PyPI publishing

Not configured. Adding it is straightforward — add a third job that uses
`pypa/gh-action-pypi-publish@release/v1` with PyPI Trusted Publishing
configured for the repo. Out of scope for the initial release.
