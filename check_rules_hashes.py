import hashlib
import os

def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

rules_dir = 'rules'
if not os.path.exists(rules_dir):
    print("No rules dir")
else:
    for fname in sorted(os.listdir(rules_dir)):
        path = os.path.join(rules_dir, fname)
        if os.path.isfile(path):
            with open(path, 'rb') as f:
                content = f.read()
            h = sha256(content)
            h_strip = sha256(content.strip())
            print(f"{fname}:")
            print(f"  Raw: {h}")
            print(f"  Strip: {h_strip}")

print("Hash to match: 8ddecb4385884e2e20aba60bbf702c073031732c94ba4fb7d6bf7f98bab4d175")
