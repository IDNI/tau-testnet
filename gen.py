import os
import py_ecc.bls as bls
from py_ecc.bls import G2ProofOfPossession as bls

def generate_bls12_381_keypair():
    """
    Generates a sample BLS12-381 key pair.
    Returns:
        tuple: (private_key_hex, public_key_hex)
    """
    # Generate a 32-byte random seed for the private key.
    # For actual use, ensure this seed comes from a cryptographically secure random number generator.
    seed = os.urandom(32)

    # 1. Generate Private Key
    # bls.KeyGen derives a private key from the seed.
    # The private key (sk) is an integer 0 < sk < r (where r is the curve order).
    # py_ecc's bls module uses a default domain for KeyGen that is suitable for general use.
    private_key_int = bls.KeyGen(seed)

    # 2. Generate Public Key
    # bls.SkToPk computes pk = sk * G1_generator and returns its byte representation.
    # For BLS12-381, public keys in G1 are 48 bytes (compressed).
    public_key_bytes = bls.SkToPk(private_key_int)

    # --- Prepare keys for output ---
    # Private keys are typically 32 bytes long (representing a ~255-bit integer)
    private_key_hex = private_key_int.to_bytes(32, 'big').hex()

    # Public keys (G1 points for BLS12-381) are 48 bytes when compressed
    public_key_hex = public_key_bytes.hex()

    return private_key_int, private_key_hex, public_key_bytes.hex()

if __name__ == "__main__":
    # This part will only run if you execute the script directly.
    # If you run this in an environment without py_ecc, it will fail here.
    # In an environment WITH py_ecc:
    try:
        # For checking properties if py_ecc is available
        from py_ecc.optimized_bls12_381 import curve_order

        private_key_as_int, priv_hex, pub_hex = generate_bls12_381_keypair()

        print(f"BLS12-381 Key Pair (using py_ecc default scheme, pk in G1):")
        print(f"----------------------------------------------------------")
        print(f"Private Key (integer): {private_key_as_int}")
        print(f"Private Key (hex, 32 bytes): {priv_hex}")
        print(f"Public Key (hex, 48 bytes, G1 compressed): {pub_hex}")
        print(f"----------------------------------------------------------")
        print(f"Note: The curve order r for BLS12-381 is approximately 2^255.")
        print(f"Curve order r: {curve_order}")

        # Basic sanity checks (will only run if py_ecc is available)
        assert 0 < private_key_as_int < curve_order
        assert len(bytes.fromhex(pub_hex)) == 48
        print("Assertions for key validity passed (if py_ecc was available).")

    except ModuleNotFoundError:
        print("py_ecc module not found. Please install it with 'pip install py_ecc' to run this script.")
        print("\n--- Sample Key Structure (if generated) ---")
        print("Private Key (hex, 32 bytes): <64 hexadecimal characters>")
        print("Public Key (hex, 48 bytes, G1 compressed): <96 hexadecimal characters>")
