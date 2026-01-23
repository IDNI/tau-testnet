
import os
import sys

# Ensure we can import from the current directory if running as a script
sys.path.append(os.getcwd())

try:
    from scripts.gen import generate_bls12_381_keypair
except ImportError:
    # Fallback if running directly from scripts/ directory
    sys.path.append(os.path.join(os.getcwd(), '..'))
    from scripts.gen import generate_bls12_381_keypair

def main():
    print("Generating BLS12-381 keypair for miner...")
    _, priv_hex, pub_hex = generate_bls12_381_keypair()

    priv_file = "test_miner.key"
    pub_file = "test_miner.pub"

    with open(priv_file, "w") as f:
        f.write(priv_hex)
    
    with open(pub_file, "w") as f:
        f.write(pub_hex)

    print(f"Successfully generated keys:")
    print(f"  Private Key saved to: {priv_file}")
    print(f"  Public Key saved to:  {pub_file}")
    print("\nTo use these for the local miner, move them to the data directory:")
    print(f"  mv {priv_file} {pub_file} data/")

if __name__ == "__main__":
    main()
