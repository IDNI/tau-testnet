import os
import sys
import unittest
import hashlib
import json
import time

# Ensure project root is on sys.path so that block.py is importable
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
from block import Block, BlockHeader, compute_tx_hash, compute_merkle_root
from commands import createblock
from db import init_db, add_mempool_tx, get_latest_block, clear_mempool
import config


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


class TestBlockCreation(unittest.TestCase):
    
    def setUp(self):
        """Set up a temporary database for testing block creation."""
        self.test_db_path = "test_blockchain_db.sqlite"
        config.STRING_DB_PATH = self.test_db_path
        init_db()
        
        self.tx1_json = json.dumps({"sender": "a", "recipient": "b", "amount": 10, "operations": {"1": []}})
        self.tx2_json = json.dumps({"sender": "c", "recipient": "d", "amount": 20, "operations": {"1": []}})

    def tearDown(self):
        """Clean up the temporary database."""
        clear_mempool()
        # Close the connection if it's open, to release file lock on Windows
        if hasattr(createblock.db, '_db_conn') and createblock.db._db_conn is not None:
            createblock.db._db_conn.close()
            createblock.db._db_conn = None
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        # Restore original db path if needed elsewhere
        config.STRING_DB_PATH = config.DEFAULT_PROD_DB_PATH

    def test_genesis_block_creation(self):
        """Test creating the first block (genesis block) from the mempool."""
        # Add transactions to mempool
        add_mempool_tx(self.tx1_json)
        
        # Create block
        created_block_data = createblock.create_block_from_mempool()
        self.assertIsNotNone(created_block_data)
        
        # Verify from DB
        latest_block = get_latest_block()
        self.assertIsNotNone(latest_block)
        
        self.assertEqual(latest_block['header']['block_number'], 0)
        self.assertEqual(latest_block['header']['previous_hash'], "0" * 64)
        self.assertEqual(len(latest_block['transactions']), 1)
        self.assertEqual(latest_block['transactions'][0], json.loads(self.tx1_json))
        self.assertEqual(latest_block['block_hash'], created_block_data['block_hash'])

    def test_subsequent_block_creation(self):
        """Test creating a second block that links to the genesis block."""
        # 1. Create and save a genesis block
        add_mempool_tx(self.tx1_json)
        genesis_block_data = createblock.create_block_from_mempool()
        genesis_hash = genesis_block_data['block_hash']
        
        # 2. Add new tx and create the next block
        add_mempool_tx(self.tx2_json)
        next_block_data = createblock.create_block_from_mempool()

        # 3. Verify the new block from DB
        latest_block = get_latest_block()
        self.assertIsNotNone(latest_block)
        
        self.assertEqual(latest_block['header']['block_number'], 1)
        self.assertEqual(latest_block['header']['previous_hash'], genesis_hash)
        self.assertEqual(len(latest_block['transactions']), 1)
        self.assertEqual(latest_block['transactions'][0], json.loads(self.tx2_json))
        self.assertEqual(latest_block['block_hash'], next_block_data['block_hash'])

    def test_create_block_with_empty_mempool(self):
        """Test that no block is created if the mempool is empty."""
        # Ensure mempool is empty
        clear_mempool()
        
        # Attempt to create a block
        result = createblock.create_block_from_mempool()
        
        # Verify no block was created
        self.assertIn("Mempool is empty", result.get("message", ""))
        
        # Verify database has no blocks
        latest_block = get_latest_block()
        self.assertIsNone(latest_block)


if __name__ == '__main__':
    unittest.main()