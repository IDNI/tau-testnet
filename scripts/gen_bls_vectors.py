#!/usr/bin/env python
"""Regenerate the BLS differential fixtures under tests/fixtures/.

bls_g2basic_vectors.json: `expected` is py_ecc's G2Basic.Verify on (pk, msg, sig).
bls_header_vectors.json: `expected` is G2Basic.Verify on a block header's proposer,
proof and header digest.

py_ecc is the reference the consensus verifier must match on every input. Inputs
are built with arkworks (byte-identical to py_ecc, far faster) and are fully
determined by SEED.

    venv/bin/python scripts/gen_bls_vectors.py [--out PATH]
"""
import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from py_arkworks_bls12381 import G1Point, G2Point  # noqa: E402
from py_ecc.bls import G2Basic  # noqa: E402
from py_ecc.bls.g2_primitives import (  # noqa: E402
    G1_to_pubkey,
    G2_to_signature,
    pubkey_to_G1,
    signature_to_G2,
)
from py_ecc.bls.point_compression import modular_squareroot_in_FQ2  # noqa: E402
from py_ecc.fields import optimized_bls12_381_FQ as FQ  # noqa: E402
from py_ecc.fields import optimized_bls12_381_FQ2 as FQ2  # noqa: E402
from py_ecc.optimized_bls12_381 import (  # noqa: E402
    add,
    b,
    b2,
    curve_order,
    is_inf,
    is_on_curve,
    multiply,
)
from py_ecc.optimized_bls12_381 import field_modulus as Q  # noqa: E402

from block import BlockHeader  # noqa: E402
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex, sign_message  # noqa: E402

SEED = 20261102
DEFAULT_OUT = ROOT / "tests" / "fixtures" / "bls_g2basic_vectors.json"
HEADER_OUT = ROOT / "tests" / "fixtures" / "bls_header_vectors.json"
N_HEADER_VALID = 30
N_VALID = 50
N_MUTANT_PK = 100
N_MUTANT_SIG = 100
N_MUTANT_MSG = 50
N_SWEEP_PER_FIELD = 17

P381 = 1 << 381
H1 = 0x396C8C005555E1568C00AAAB0000AAAB
H2 = 305502333931268344200999753193121504214466019254188142667664032982267604182971884026507427359259977847832272839041616661285803823378372096355777062779109


def be(z, n):
    return z.to_bytes(n, "big")


def g1_enc(c, bf, a, body):
    return be((c << 383) | (bf << 382) | (a << 381) | body, 48)


def g2_enc(c, bf, a, x1, z2):
    return g1_enc(c, bf, a, x1) + be(z2, 48)


def split_g1(pk):
    z = int.from_bytes(pk, "big")
    return (z >> 383) & 1, (z >> 382) & 1, (z >> 381) & 1, z & (P381 - 1)


def split_g2(sig):
    z1 = int.from_bytes(sig[:48], "big")
    z2 = int.from_bytes(sig[48:], "big")
    return (z1 >> 383) & 1, (z1 >> 382) & 1, (z1 >> 381) & 1, z1 & (P381 - 1), z2


def flip_sort(data):
    return bytes([data[0] ^ 0x20]) + data[1:]


def pk_of(sk):
    return bytes.fromhex(pubkey_hex(sk))


def rand_msg(rng):
    return hashlib.sha256(rng.randbytes(16)).digest()


def rand_sk(rng):
    return rng.randrange(1, curve_order)


def rand_g1_curve_point(rng):
    while True:
        x = rng.randrange(Q)
        rhs = (x**3 + 4) % Q
        y = pow(rhs, (Q + 1) // 4, Q)
        if y * y % Q == rhs:
            return (FQ(x), FQ(y), FQ(1))


def rand_g2_curve_point(rng):
    while True:
        x = FQ2([rng.randrange(Q), rng.randrange(Q)])
        y = modular_squareroot_in_FQ2(x**3 + b2)
        if y is not None:
            return (x, y, FQ2([1, 0]))


def small_order_points(pt, cofactor, factors):
    t = multiply(pt, curve_order)
    out = [t]
    for f in factors:
        assert cofactor % f == 0
        s = multiply(t, cofactor // f)
        if not is_inf(s):
            out.append(s)
    return [p for p in out if not is_inf(p)]


def mutate(rng, data):
    n = len(data)
    z = bytearray(data)
    kind = rng.randrange(7)
    if kind == 0:
        z[0] ^= 1 << rng.randrange(8)
    elif kind == 1:
        z[rng.randrange(n)] = rng.randrange(256)
    elif kind == 2:
        # Shift a coordinate by a multiple of p: congruent but non-canonical.
        i0 = 48 * rng.randrange(n // 48)
        v = int.from_bytes(z[i0 : i0 + 48], "big")
        flags, body = v >> 381 << 381, v & (P381 - 1)
        z[i0 : i0 + 48] = be(flags | ((body + rng.choice([Q, -Q, 1, -1, 2 * Q])) % P381), 48)
    elif kind == 3:
        z[rng.randrange(n)] ^= 1 << rng.randrange(8)
    elif kind == 4:
        z[0] = (z[0] & 0x1F) | (rng.randrange(8) << 5)
    elif kind == 5 and n == 96:
        z[48] = (z[48] & 0x1F) | (rng.randrange(8) << 5)
    else:
        for _ in range(rng.randrange(1, 4)):
            z[rng.randrange(n)] = rng.randrange(256)
    return bytes(z)


class Corpus:
    def __init__(self):
        self.cases = []

    def add(self, label, pk, msg, sig):
        assert all(isinstance(v, bytes) for v in (pk, msg, sig)), label
        self.cases.append((label, pk, msg, sig))


def add_valid(c, rng):
    for _ in range(N_VALID):
        sk = rand_sk(rng)
        # Digests are what transactions sign; the odd lengths exercise hash_to_curve.
        msg = rand_msg(rng) if rng.random() < 0.8 else rng.randbytes(rng.randrange(0, 200))
        c.add("valid", pk_of(sk), msg, sign_message(sk, msg))


def add_edge(c, rng):
    fix = []
    for _ in range(4):
        sk = rand_sk(rng)
        msg = rand_msg(rng)
        fix.append((sk, pk_of(sk), msg, sign_message(sk, msg)))
    sk0, pk0, msg0, sig0 = fix[0]
    sk1, pk1, msg1, sig1 = fix[1]
    for sk, pk, msg, sig in fix:
        c.add("baseline_valid", pk, msg, sig)

    for _ in range(5):
        c.add("wrong_msg", pk0, rand_msg(rng), sig0)
        c.add("wrong_pk", pk1, msg0, sig0)
        c.add("sig_from_other_key", pk0, msg0, sign_message(rand_sk(rng), msg0))
        c.add("sig_over_other_msg", pk0, msg0, sign_message(sk0, rand_msg(rng)))
    c.add("wrong_pk_and_msg", pk1, msg1 + b"x", sig0)

    id_pk = bytes([0xC0]) + bytes(47)
    id_sig = bytes([0xC0]) + bytes(95)
    for _ in range(3):
        m = rand_msg(rng)
        c.add("identity_pk_valid_sig", id_pk, m, sign_message(sk0, m))
        c.add("identity_sig_valid_pk", pk0, m, id_sig)
        c.add("identity_both", id_pk, m, id_sig)
    for first in (0xE0, 0x80, 0x40, 0xA0, 0x00, 0x20, 0x60):
        c.add("identity_variant_flags_pk", bytes([first]) + bytes(47), msg0, sig0)
        c.add("identity_variant_flags_sig", pk0, msg0, bytes([first]) + bytes(95))
        c.add("identity_variant_flags_both", bytes([first]) + bytes(47), msg0, bytes([first]) + bytes(95))

    pk_bad, sig_bad = [], []
    for _ in range(5):
        p = rand_g1_curve_point(rng)
        assert not is_inf(multiply(p, curve_order))
        pk_bad.append(("g1_random_coset_point", G1_to_pubkey(p)))
        for t in small_order_points(p, H1, [3, 11, 10177, 859267, 52437899])[:3]:
            pk_bad.append(("g1_torsion_point", G1_to_pubkey(t)))
            pk_bad.append(("g1_valid_plus_torsion", G1_to_pubkey(add(pubkey_to_G1(pk0), t))))
    t3 = (FQ(0), FQ(2), FQ(1))
    assert is_on_curve(t3, b)
    pk_bad.append(("g1_3torsion_x0", G1_to_pubkey(t3)))
    pk_bad.append(("g1_valid_plus_3torsion_x0", G1_to_pubkey(add(pubkey_to_G1(pk0), t3))))
    for _ in range(5):
        p = rand_g2_curve_point(rng)
        assert not is_inf(multiply(p, curve_order))
        sig_bad.append(("g2_random_coset_point", G2_to_signature(p)))
        for t in small_order_points(p, H2, [13, 23, 2713, 11953, 262069])[:3]:
            sig_bad.append(("g2_torsion_point", G2_to_signature(t)))
            sig_bad.append(("g2_valid_plus_torsion", G2_to_signature(add(signature_to_G2(sig0), t))))
    for label, enc in pk_bad:
        for e in (enc, flip_sort(enc)):
            c.add(f"nonsubgroup:{label}", e, msg0, sig0)
    for label, enc in sig_bad:
        for e in (enc, flip_sort(enc)):
            c.add(f"nonsubgroup:{label}", pk0, msg0, e)
    c.add("nonsubgroup:both", pk_bad[0][1], msg0, sig_bad[0][1])

    def find(pred_pk=None, pred_sig=None, count=3):
        got = []
        while len(got) < count:
            sk = rand_sk(rng)
            msg = rand_msg(rng)
            pk, sig = pk_of(sk), sign_message(sk, msg)
            _, _, _, xb = split_g1(pk)
            _, _, _, x1, x2 = split_g2(sig)
            if pred_pk and not pred_pk(xb):
                continue
            if pred_sig and not pred_sig(x1, x2):
                continue
            got.append((sk, pk, msg, sig))
        return got

    room = P381 - Q  # x + p still fits in 381 bits only when x < room
    for sk, pk, msg, sig in find(pred_pk=lambda x: x < room, count=4):
        cc, bf, a, x = split_g1(pk)
        c.add("noncanon:pk_baseline_valid", pk, msg, sig)
        c.add("noncanon:pk_x_plus_p", g1_enc(cc, bf, a, x + Q), msg, sig)
        c.add("noncanon:pk_x_plus_p_flipsort", g1_enc(cc, bf, 1 - a, x + Q), msg, sig)
    for sk, pk, msg, sig in find(pred_sig=lambda x1, x2: x1 < room, count=3):
        cc, bf, a, x1, x2 = split_g2(sig)
        c.add("noncanon:sig_c1_plus_p", pk, msg, g2_enc(cc, bf, a, x1 + Q, x2))
    for sk, pk, msg, sig in find(pred_sig=lambda x1, x2: x2 < room, count=3):
        cc, bf, a, x1, x2 = split_g2(sig)
        c.add("noncanon:sig_c0_plus_p", pk, msg, g2_enc(cc, bf, a, x1, x2 + Q))
    for sk, pk, msg, sig in find(pred_sig=lambda x1, x2: x1 < room and x2 < room, count=3):
        cc, bf, a, x1, x2 = split_g2(sig)
        c.add("noncanon:sig_both_plus_p", pk, msg, g2_enc(cc, bf, a, x1 + Q, x2 + Q))
    for sk, pk, msg, sig in fix[:2]:
        cc, bf, a, xb = split_g1(pk)
        for v in (Q, Q + 1, Q + 5, P381 - 1):
            c.add("noncanon:pk_body_ge_p", g1_enc(cc, bf, a, v), msg, sig)
        cc, bf, a, x1, x2 = split_g2(sig)
        for v in (Q, Q + 1, P381 - 1):
            c.add("noncanon:sig_c1_ge_p", pk, msg, g2_enc(cc, bf, a, v, x2))
            c.add("noncanon:sig_c0_ge_p", pk, msg, g2_enc(cc, bf, a, x1, v))

    for sk, pk, msg, sig in fix[:2]:
        cc, bf, a, xb = split_g1(pk)
        _, _, _, x1, x2 = split_g2(sig)
        c.add("flags:pk_compression_cleared", g1_enc(0, bf, a, xb), msg, sig)
        c.add("flags:sig_compression_cleared", pk, msg, g2_enc(0, 0, split_g2(sig)[2], x1, x2))
        for c_bit in (0, 1):
            for b_bit in (0, 1):
                for a_bit in (0, 1):
                    c.add("flags:pk_all_flag_combos", g1_enc(c_bit, b_bit, a_bit, xb), msg, sig)
                    c.add("flags:sig_all_flag_combos", pk, msg, g2_enc(c_bit, b_bit, a_bit, x1, x2))
        for top in range(1, 8):
            c.add("flags:sig_second_half_flags", pk, msg, sig[:48] + be(x2 | (top << 381), 48))
        c.add("flags:sig_sort_flipped", pk, msg, flip_sort(sig))
        c.add("flags:pk_sort_flipped", flip_sort(pk), msg, sig)
        c.add("flags:pk_inf_flag_nonzero_body", g1_enc(1, 1, a, xb), msg, sig)
        c.add("flags:pk_inf_flag_tiny_body", g1_enc(1, 1, 0, 1), msg, sig)
        c.add("flags:sig_inf_flag_nonzero_c1", pk, msg, g2_enc(1, 1, 0, x1, 0))
        c.add("flags:sig_inf_flag_nonzero_c0", pk, msg, g2_enc(1, 1, 0, 0, x2))
        c.add("flags:sig_inf_flag_nonzero_both", pk, msg, g2_enc(1, 1, a, x1, x2))
        c.add("flags:sig_inf_flag_tiny_c0", pk, msg, g2_enc(1, 1, 0, 0, 1))
        c.add("flags:sig_inf_flag_tiny_c1", pk, msg, g2_enc(1, 1, 0, 1, 0))
        c.add("flags:pk_zero_body_no_inf_flag", g1_enc(1, 0, 0, 0), msg, sig)
        c.add("flags:pk_zero_body_no_inf_flag_a", g1_enc(1, 0, 1, 0), msg, sig)
        c.add("flags:sig_c1_zero_real_x", pk, msg, g2_enc(1, 0, 0, 0, x2))
        c.add("flags:sig_c1_zero_real_x_a", pk, msg, g2_enc(1, 0, 1, 0, x2))
        c.add("flags:sig_zero_body_no_inf_flag", pk, msg, g2_enc(1, 0, 0, 0, 0))
    c.add("flags:pk_inf_with_sort", g1_enc(1, 1, 1, 0), msg0, sig0)
    c.add("flags:sig_inf_with_sort", pk0, msg0, g2_enc(1, 1, 1, 0, 0))

    for n in (0, 47, 49, 95, 97, 96, 144, 192):
        c.add("len:pk", bytes(n), msg0, sig0)
        c.add("len:pk_random", rng.randbytes(n), msg0, sig0)
    for n in (0, 47, 48, 49, 95, 97, 144, 192):
        c.add("len:sig", pk0, msg0, bytes(n))
        c.add("len:sig_random", pk0, msg0, rng.randbytes(n))
    c.add("len:pk_truncated_valid", pk0[:47], msg0, sig0)
    c.add("len:pk_padded_valid", pk0 + b"\x00", msg0, sig0)
    c.add("len:pk_prefixed_valid", b"\x00" + pk0, msg0, sig0)
    c.add("len:sig_truncated_valid", pk0, msg0, sig0[:95])
    c.add("len:sig_padded_valid", pk0, msg0, sig0 + b"\x00")
    c.add("len:sig_prefixed_valid", pk0, msg0, b"\x00" + sig0)
    c.add("len:pk_is_sig", sig0, msg0, sig0)
    c.add("len:sig_is_pk", pk0, msg0, pk0)
    c.add("len:swapped", sig0, msg0, pk0)

    for n in (0, 1, 31, 32, 33, 64, 1000):
        m = b"" if n == 0 else rng.randbytes(n)
        sk = rand_sk(rng)
        pk = pk_of(sk)
        sig = sign_message(sk, m)
        c.add(f"msglen:{n}", pk, m, sig)
        c.add(f"msglen_wrong:{n}", pk, m + b"\x00", sig)

    for _ in range(20):
        c.add("random_bytes:pk48", rng.randbytes(48), msg0, sig0)
        c.add("random_bytes:sig96", pk0, msg0, rng.randbytes(96))
        c.add("random_bytes:both", rng.randbytes(48), msg0, rng.randbytes(96))


def add_fuzz(c, rng):
    sk = rand_sk(rng)
    msg = rand_msg(rng)
    pk0, sig0 = pk_of(sk), sign_message(sk, msg)
    for v in rng.sample(range(256), N_SWEEP_PER_FIELD):
        c.add("sweep:pk_first_byte", bytes([v]) + pk0[1:], msg, sig0)
    for v in rng.sample(range(256), N_SWEEP_PER_FIELD):
        c.add("sweep:sig_first_byte", pk0, msg, bytes([v]) + sig0[1:])
    for v in rng.sample(range(256), N_SWEEP_PER_FIELD):
        c.add("sweep:sig_byte48", pk0, msg, sig0[:48] + bytes([v]) + sig0[49:])
    for _ in range(N_MUTANT_PK):
        c.add("mutant:pk", mutate(rng, pk0), msg, sig0)
    for _ in range(N_MUTANT_SIG):
        c.add("mutant:sig", pk0, msg, mutate(rng, sig0))
    for _ in range(N_MUTANT_MSG):
        c.add("mutant:msg", pk0, rng.randbytes(rng.randrange(0, 70)), sig0)


def build():
    rng = random.Random(SEED)
    c = Corpus()
    add_valid(c, rng)
    add_edge(c, rng)
    add_fuzz(c, rng)
    return c.cases


def edge_pubkeys(rng, pk0):
    """Distinct 48-byte keys that stress canonical-encoding, subgroup and flag handling."""
    out = []
    for first in (0xC0, 0xE0, 0x80, 0x40, 0xA0, 0x00, 0x20, 0x60):
        out.append(("identity_variant", bytes([first]) + bytes(47)))
    out.append(("flags:inf_with_sort", g1_enc(1, 1, 1, 0)))
    out.append(("flags:zero_body_no_inf_flag", g1_enc(1, 0, 0, 0)))
    out.append(("flags:zero_body_no_inf_flag_a", g1_enc(1, 0, 1, 0)))
    out.append(("flags:inf_flag_tiny_body", g1_enc(1, 1, 0, 1)))
    cc, bf, a, xb = split_g1(pk0)
    out.append(("flags:inf_flag_nonzero_body", g1_enc(1, 1, a, xb)))
    out.append(("flags:compression_cleared", g1_enc(0, bf, a, xb)))
    out.append(("flags:sort_flipped", flip_sort(pk0)))
    for c_bit in (0, 1):
        for b_bit in (0, 1):
            for a_bit in (0, 1):
                out.append(("flags:all_combos", g1_enc(c_bit, b_bit, a_bit, xb)))
    for v in (Q, Q + 1, Q + 5, P381 - 1):
        out.append(("noncanon:body_ge_p", g1_enc(cc, bf, a, v)))
    room = P381 - Q
    for _ in range(4):
        while True:
            pk = pk_of(rand_sk(rng))
            _, b_, a_, x = split_g1(pk)
            if x < room:
                break
        out.append(("noncanon:x_plus_p", g1_enc(1, b_, a_, x + Q)))
        out.append(("noncanon:x_plus_p_flipsort", g1_enc(1, b_, 1 - a_, x + Q)))
    for _ in range(5):
        p = rand_g1_curve_point(rng)
        assert not is_inf(multiply(p, curve_order))
        out.append(("nonsubgroup:coset_point", G1_to_pubkey(p)))
        for t in small_order_points(p, H1, [3, 11, 10177, 859267, 52437899])[:3]:
            out.append(("nonsubgroup:torsion_point", G1_to_pubkey(t)))
            out.append(("nonsubgroup:valid_plus_torsion", G1_to_pubkey(add(pubkey_to_G1(pk0), t))))
    t3 = (FQ(0), FQ(2), FQ(1))
    assert is_on_curve(t3, b)
    out.append(("nonsubgroup:3torsion_x0", G1_to_pubkey(t3)))
    out.append(("nonsubgroup:valid_plus_3torsion_x0", G1_to_pubkey(add(pubkey_to_G1(pk0), t3))))
    for label, enc in list(out):
        if label.startswith("nonsubgroup"):
            out.append((label + "_flipsort", flip_sort(enc)))
    return out


def dedupe(cases):
    seen = set()
    out = []
    for label, key in cases:
        if key not in seen:
            seen.add(key)
            out.append((label, key))
    return out


def edge_proofs(rng, sig0):
    """96-byte proofs that stress canonical-encoding, subgroup and flag handling."""
    out = []
    for first in (0xC0, 0xE0, 0x80, 0x40, 0xA0, 0x00, 0x20, 0x60):
        out.append(("identity_variant", bytes([first]) + bytes(95)))
    out.append(("flags:inf_with_sort", g2_enc(1, 1, 1, 0, 0)))
    out.append(("flags:zero_body_no_inf_flag", g2_enc(1, 0, 0, 0, 0)))
    cc, bf, a, x1, x2 = split_g2(sig0)
    out.append(("flags:compression_cleared", g2_enc(0, 0, a, x1, x2)))
    out.append(("flags:sort_flipped", flip_sort(sig0)))
    out.append(("flags:inf_flag_nonzero_c1", g2_enc(1, 1, 0, x1, 0)))
    out.append(("flags:inf_flag_nonzero_c0", g2_enc(1, 1, 0, 0, x2)))
    out.append(("flags:inf_flag_tiny_c0", g2_enc(1, 1, 0, 0, 1)))
    for top in range(1, 8):
        out.append(("flags:second_half_flags", sig0[:48] + be(x2 | (top << 381), 48)))
    for c_bit in (0, 1):
        for b_bit in (0, 1):
            for a_bit in (0, 1):
                out.append(("flags:all_combos", g2_enc(c_bit, b_bit, a_bit, x1, x2)))
    for v in (Q, Q + 1, P381 - 1):
        out.append(("noncanon:c1_ge_p", g2_enc(cc, bf, a, v, x2)))
        out.append(("noncanon:c0_ge_p", g2_enc(cc, bf, a, x1, v)))
    room = P381 - Q
    for _ in range(3):
        while True:
            sig = sign_message(rand_sk(rng), rand_msg(rng))
            _, b_, a_, y1, y2 = split_g2(sig)
            if y1 < room and y2 < room:
                break
        out.append(("noncanon:c1_plus_p", g2_enc(1, b_, a_, y1 + Q, y2)))
        out.append(("noncanon:c0_plus_p", g2_enc(1, b_, a_, y1, y2 + Q)))
        out.append(("noncanon:both_plus_p", g2_enc(1, b_, a_, y1 + Q, y2 + Q)))
    for _ in range(5):
        p = rand_g2_curve_point(rng)
        assert not is_inf(multiply(p, curve_order))
        out.append(("nonsubgroup:coset_point", G2_to_signature(p)))
        for t in small_order_points(p, H2, [13, 23, 2713, 11953, 262069])[:3]:
            out.append(("nonsubgroup:torsion_point", G2_to_signature(t)))
            out.append(("nonsubgroup:valid_plus_torsion", G2_to_signature(add(signature_to_G2(sig0), t))))
    for label, enc in list(out):
        if label.startswith("nonsubgroup"):
            out.append((label + "_flipsort", flip_sort(enc)))
    return dedupe(out)


def header_digest(h):
    return hashlib.sha256(h.canonical_bytes()).digest()


def build_headers():
    """(label, header fields, proof bytes) cases; `expected` is added from py_ecc."""
    rng = random.Random(SEED + 1)
    proposers = [SK_ALICE, SK_BOB, SK_CAROL]

    def rand_header(sk):
        return BlockHeader(
            block_number=rng.randrange(1, 1 << 40),
            previous_hash=rng.randbytes(32).hex(),
            timestamp=rng.randrange(1, 1 << 40),
            merkle_root=rng.randbytes(32).hex(),
            proposer_pubkey=pubkey_hex(sk),
            state_hash=rng.randbytes(32).hex(),
        )

    def signed(h, sk):
        return sign_message(sk, header_digest(h))

    def with_field(h, **over):
        d = {
            "block_number": h.block_number,
            "previous_hash": h.previous_hash,
            "timestamp": h.timestamp,
            "merkle_root": h.merkle_root,
            "proposer_pubkey": h.proposer_pubkey,
            "state_hash": h.state_hash,
        }
        d.update(over)
        return BlockHeader(**d)

    cases = []

    def add(label, h, proof):
        assert isinstance(proof, bytes), label
        cases.append((label, h, proof))

    for i in range(N_HEADER_VALID):
        sk = proposers[i % 3]
        h = rand_header(sk)
        add("valid", h, signed(h, sk))

    sk0 = SK_ALICE
    base = rand_header(sk0)
    base_proof = signed(base, sk0)
    add("valid_baseline", base, base_proof)
    for _ in range(3):
        sk = rng.choice(proposers)
        h = rand_header(sk)
        proof = signed(h, sk)
        tampers = {
            "block_number": with_field(h, block_number=h.block_number + 1),
            "previous_hash": with_field(h, previous_hash=rng.randbytes(32).hex()),
            "timestamp": with_field(h, timestamp=h.timestamp + 1),
            "merkle_root": with_field(h, merkle_root=rng.randbytes(32).hex()),
            "state_hash": with_field(h, state_hash=rng.randbytes(32).hex()),
        }
        for name, t in tampers.items():
            add(f"tampered:{name}", t, proof)

    for _ in range(4):
        h = rand_header(SK_ALICE)
        proof = signed(h, SK_ALICE)
        add("swapped_proposer", with_field(h, proposer_pubkey=pubkey_hex(SK_BOB)), proof)
        add("sig_by_other_key", h, signed(h, SK_BOB))
        add("sig_over_other_header", h, signed(rand_header(SK_ALICE), SK_ALICE))
        # Proposer named after signing, with the digest recomputed for the new name.
        swapped = with_field(h, proposer_pubkey=pubkey_hex(SK_CAROL))
        add("sig_over_swapped_header_by_original_key", swapped, signed(swapped, SK_ALICE))

    pk0 = bytes.fromhex(pubkey_hex(SK_ALICE))
    for label, key in dedupe(edge_pubkeys(rng, pk0)):
        h = with_field(base, proposer_pubkey=key.hex())
        add(f"edge_pubkey:{label}", h, signed(h, SK_ALICE))
        add(f"edge_pubkey_base_proof:{label}", h, base_proof)

    for label, enc in edge_proofs(rng, base_proof):
        add(f"edge_proof:{label}", base, enc)
    return cases


def write_fixture(path, seed_label, rows):
    body = ",\n".join(json.dumps(v, sort_keys=True) for v in rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'{{\n"seed": {seed_label},\n"vectors": [\n{body}\n]\n}}\n')
    accepted = sum(v["expected"] for v in rows)
    print(f"wrote {len(rows)} vectors ({accepted} accepted) to {path}")


def verify_oracle(pk, digest, sig):
    return bool(G2Basic.Verify(pk, digest, sig))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--header-out", type=Path, default=HEADER_OUT)
    args = ap.parse_args()

    vectors = []
    for label, pk, msg, sig in build():
        vectors.append(
            {
                "label": label,
                "pk": pk.hex(),
                "msg": msg.hex(),
                "sig": sig.hex(),
                "expected": verify_oracle(pk, msg, sig),
            }
        )
    write_fixture(args.out, SEED, vectors)

    headers = []
    for label, h, proof in build_headers():
        digest = header_digest(h)
        headers.append(
            {
                "label": label,
                "header": {
                    "block_number": h.block_number,
                    "previous_hash": h.previous_hash,
                    "timestamp": h.timestamp,
                    "merkle_root": h.merkle_root,
                    "state_hash": h.state_hash,
                },
                "proposer": h.proposer_pubkey,
                "proof": proof.hex(),
                "expected": verify_oracle(bytes.fromhex(h.proposer_pubkey), digest, proof),
            }
        )
    write_fixture(args.header_out, SEED + 1, headers)


if __name__ == "__main__":
    main()
