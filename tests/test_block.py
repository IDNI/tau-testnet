import unittest
import hashlib
from block import compute_tx_hash, compute_merkle_root, Block


class TestMerkleRoot(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(
            compute_merkle_root([]),
            hashlib.sha256(b'').hexdigest()
        )

    def test_single(self):
        data = hashlib.sha256(b'test').hexdigest()
        self.assertEqual(compute_merkle_root([data]), data)

    def test_two(self):
        h1 = hashlib.sha256(b'a').hexdigest()
        h2 = hashlib.sha256(b'b').hexdigest()
        expected = hashlib.sha256(bytes.fromhex(h1) + bytes.fromhex(h2)).hexdigest()
        self.assertEqual(compute_merkle_root([h1, h2]), expected)

    def test_odd(self):
        h1 = hashlib.sha256(b'a').hexdigest()
        h2 = hashlib.sha256(b'b').hexdigest()
        h3 = hashlib.sha256(b'c').hexdigest()
        expected = compute_merkle_root([h1, h2, h3, h3])
        self.assertEqual(compute_merkle_root([h1, h2, h3]), expected)


class TestBlock(unittest.TestCase):
    def test_block_creation_empty(self):
        prev_hash = '00' * 32
        block = Block.create(block_number=0, previous_hash=prev_hash, transactions=[])
        self.assertEqual(block.header.block_number, 0)
        self.assertEqual(block.header.previous_hash, prev_hash)
        self.assertEqual(
            block.header.merkle_root,
            hashlib.sha256(b'').hexdigest()
        )
        self.assertEqual(len(block.block_hash), 64)
        d = block.to_dict()
        self.assertEqual(d['header']['block_number'], 0)
        self.assertEqual(d['header']['previous_hash'], prev_hash)

    def test_block_creation_with_transactions(self):
        tx1 = {"foo": "bar"}
        tx2 = {"baz": 123}
        prev_hash = 'aa' * 32
        block = Block.create(block_number=1, previous_hash=prev_hash, transactions=[tx1, tx2])
        tx_hashes = [compute_tx_hash(tx1), compute_tx_hash(tx2)]
        self.assertEqual(block.header.merkle_root, compute_merkle_root(tx_hashes))
        self.assertEqual(len(block.block_hash), 64)


if __name__ == '__main__':
    unittest.main()