import os
import sys
import tempfile
import pytest

# Add the project root to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from tau_native import TauInterface, TauEngineCrash

# The templates from web-wallet/app.js generateRandomTauRule()
def get_templates():
    # Mirror generateRandomTauRule(): read the bv[24] value inputs i1/i2 and
    # write to FREE output streams (>=12) so the demo rules never clash with
    # the protocol-reserved streams 0..11 under the engine's global typing.
    outA, outB = 12, 13
    inA, inB, inC = 1, 2, 2
    sh1, sh2 = 3, 2
    bit = 1

    hx = lambda n: f"{{ #x{n:02x} }}:bv[24]"

    return [
        "\n".join([
            "# Example 1 - Constant flag output (sanity test)",
            f"always (o{outA}[t]:bv[24] = {hx(bit)}).",
        ]),
        "\n".join([
            "# Example 2 - Threshold gate (classifier-like)",
            f"always ( ((i{inA}[t]:bv[24] + i{inB}[t]:bv[24]) >= {hx(0x80)} && o{outA}[t]:bv[24] = {hx(1)}) || ((i{inA}[t]:bv[24] + i{inB}[t]:bv[24]) < {hx(0x80)} && o{outA}[t]:bv[24] = {hx(0)}) ).",
        ]),
        "\n".join([
            "# Example 3 - Feature extraction (bit shifts + combine)",
            f"always ( o{outA}[t]:bv[24] = (i{inA}[t]:bv[24] >> {hx(sh1)}) + (i{inB}[t]:bv[24] << {hx(sh2)}) ).",
        ]),
        "\n".join([
            "# Example 4 - Multiple outputs",
            f"always ( (o{outA}[t]:bv[24] = i{inA}[t]:bv[24] + i{inB}[t]:bv[24]) && (o{outB}[t]:bv[24] = i{inC}[t]:bv[24] - i{inB}[t]:bv[24]) ).",
        ]),
        "\n".join([
            "# Example 5 - Network style rule with a score gate",
            "always (",
            f"  ((((i{inA}[t]:bv[24] * {hx(0x03)}) + (i{inB}[t]:bv[24] * {hx(0x02)})) >= {hx(0x80)})",
            f"    ? (o{outA}[t]:bv[24] = {hx(1)} && o{outB}[t]:bv[24] = {hx(0xC8)})",
            f"    : (o{outA}[t]:bv[24] = {hx(0)} && o{outB}[t]:bv[24] = {hx(0x32)}) )",
            ").",
        ]),
    ]

@pytest.mark.parametrize("rule_idx, rule_text", enumerate(get_templates()))
def test_web_wallet_example_syntax(rule_idx, rule_text):
    """Test that the web wallet example can be successfully parsed by Tau engine."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.tau', delete=False) as f:
        f.write(rule_text)
        temp_name = f.name
    
    try:
        # If the syntax is invalid, TauInterface will raise TauEngineCrash
        # because tau.get_interpreter() will fail
        iface = TauInterface(temp_name)
        assert iface.interpreter is not None
    except TauEngineCrash as e:
        pytest.fail(f"Tau engine crashed parsing example {rule_idx}:\nRule: {rule_text}\nError: {e}")
    finally:
        if os.path.exists(temp_name):
            os.remove(temp_name)
