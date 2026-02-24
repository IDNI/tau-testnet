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
    outA, outB = 5, 6
    inA, inB, inC = 1, 2, 3
    sh1, sh2 = 3, 2
    bit = 1
    
    hx = lambda n: f"{{ #x{n:02x} }}:bv[8]"
    
    return [
        f"always (o{outA}[t] = {hx(bit)}).",
        
        f"always ( ((i{inA}[t]:bv[8] + i{inB}[t]:bv[8]) >= {hx(0x80)} && o{outA}[t] = {hx(1)}) || ((i{inA}[t]:bv[8] + i{inB}[t]:bv[8]) < {hx(0x80)} && o{outA}[t] = {hx(0)}) ).",
        
        f"always ( o{outA}[t]:bv[8] = (i{inA}[t]:bv[8] >> {hx(sh1)}) + (i{inB}[t]:bv[8] << {hx(sh2)}) ).",
        
        f"always ( ((i{inA}[t]:bv[8] > i{inA}[t-1]:bv[8]) && o{outA}[t] = {hx(1)}) || ((i{inA}[t]:bv[8] <= i{inA}[t-1]:bv[8]) && o{outA}[t] = {hx(0)}) ).",
        
        f"always ( (o{outA}[t]:bv[8] = i{inA}[t]:bv[8] + i{inB}[t]:bv[8]) && (o{outB}[t]:bv[8] = i{inC}[t]:bv[8] - i{inB}[t]:bv[8]) ).",
        
        f"""always ( ex s1 ex s2 ex h1 ex h2 (
  (s1 = (i{inA}[t]:bv[8] * {hx(0x03)}) + (i{inB}[t]:bv[8] * {hx(0x02)}))
  && ((s1 >= {hx(0x80)} && h1 = {hx(1)}) || (s1 < {hx(0x80)} && h1 = {hx(0)}))
  && (s2 = (i{inC}[t]:bv[8] * {hx(0x05)}) + ({hx(0x00)} - i{inA}[t]:bv[8]))
  && ((s2 >= {hx(0x40)} && h2 = {hx(1)}) || (s2 < {hx(0x40)} && h2 = {hx(0)}))
  && (o{outB}[t]:bv[8] = (h2:bv[8] * {hx(0xc8)}) + (({hx(0x01)} - h1:bv[8]) * {hx(0x32)}))
  && ( (h2 = {hx(0)} && o{outA}[t] = {hx(1)}) || (h2 = {hx(1)} && o{outA}[t] = {hx(0)}) )
) )."""
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
