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
    
    # Keep these consistent with the current web wallet generator, which uses bv[24].
    hx = lambda n: f"{{ #x{n:02x} }}:bv[24]"

    return [
        f"always (o{outA}[t] = {hx(bit)}).",

        f"always ( ((i{inA}[t]:bv[24] + i{inB}[t]:bv[24]) >= {hx(0x80)} && o{outA}[t] = {hx(1)}) || ((i{inA}[t]:bv[24] + i{inB}[t]:bv[24]) < {hx(0x80)} && o{outA}[t] = {hx(0)}) ).",

        f"always ( o{outA}[t]:bv[24] = (i{inA}[t]:bv[24] >> {hx(sh1)}) + (i{inB}[t]:bv[24] << {hx(sh2)}) ).",

        f"always ( ((i{inA}[t]:bv[24] > i{inA}[t-1]:bv[24]) && o{outA}[t] = {hx(1)}) || ((i{inA}[t]:bv[24] <= i{inA}[t-1]:bv[24]) && o{outA}[t] = {hx(0)}) )."
    ]

@pytest.mark.parametrize("rule_idx, rule_text", enumerate(get_templates()))
def test_web_wallet_example_syntax(rule_idx, rule_text):
    """Test that the web wallet example can be successfully parsed by Tau engine."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.tau', delete=False) as f:
        f.write(rule_text)
        temp_name = f.name
    
    try:
        # If the syntax is invalid, TauInterface will raise TauEngineCrash
        # because tau.get_interpreter() will return None
        iface = TauInterface(temp_name)
        assert iface.interpreter is not None
    except TauEngineCrash as e:
        pytest.fail(f"Tau engine crashed parsing example {rule_idx}:\nRule: {rule_text}\nError: {e}")
    finally:
        if os.path.exists(temp_name):
            os.remove(temp_name)
