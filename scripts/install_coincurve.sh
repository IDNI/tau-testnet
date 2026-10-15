#!/bin/sh
# coincurve 21.0.0 has no cp314 wheel, and its sdist build hook cannot find the
# LICENSE that cffi 2.x ships under dist-info/licenses/; patch the hook and build locally.
set -eu
VERSION="${COINCURVE_VERSION:-21.0.0}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python -m pip install --upgrade pip
python -m pip install "cffi==2.0.0" setuptools hatchling "scikit-build-core>=0.9.0" cmake ninja
python - "$VERSION" "$WORK" <<'PY'
import hashlib, json, sys, urllib.request
version, work = sys.argv[1:]
with urllib.request.urlopen(f"https://pypi.org/pypi/coincurve/{version}/json") as r:
    sdist = next(u for u in json.load(r)["urls"] if u["packagetype"] == "sdist")
data = urllib.request.urlopen(sdist["url"]).read()
assert hashlib.sha256(data).hexdigest() == sdist["digests"]["sha256"]
open(f"{work}/coincurve-{version}.tar.gz", "wb").write(data)
PY
tar -xzf "$WORK"/coincurve-"$VERSION".tar.gz -C "$WORK"
SRC="$WORK/coincurve-$VERSION"
sed -i.bak 's/f\.parent\.name\.endswith("\.dist-info")/".dist-info" in str(f.parent)/' "$SRC/hatch_build.py"
grep -q '".dist-info" in str(f.parent)' "$SRC/hatch_build.py"
python -m pip wheel --no-build-isolation --no-deps "$SRC" -w "$WORK/wheels"
python -m pip install "$WORK"/wheels/coincurve-*.whl
