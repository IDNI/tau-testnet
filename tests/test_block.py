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
from block import (
    Block,
    BlockHeader,
    compute_tx_hash,
    compute_merkle_root,
    bls_signing_available,
    EMPTY_STATE_HASH,
)
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
        self.assertEqual(block.header.state_hash, EMPTY_STATE_HASH)
        self.assertEqual(block.tx_ids, [])
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
        self.assertEqual(block.tx_ids, tx_hashes)
        self.assertEqual(len(block.block_hash), 64)

    @unittest.skipUnless(bls_signing_available(), "py_ecc is required for signature tests")
    def test_block_signature_roundtrip(self):
        prev_hash = 'bb' * 32
        block = Block.create(
            block_number=2,
            previous_hash=prev_hash,
            transactions=[{"foo": "bar"}],
            state_hash="12" * 32,
            signing_key_hex=config.MINER_PRIVKEY,
        )
        self.assertIsNotNone(block.block_signature)
        self.assertTrue(block.verify_signature(config.MINER_PUBKEY))


class TestBlockCreation(unittest.TestCase):
    
    def setUp(self):
        """Set up a temporary database for testing block creation."""
        self.test_db_path = "test_blockchain_db.sqlite"
        config.set_database_path(self.test_db_path)
        init_db()
        
        # Reset chain state globals to ensure isolation
        import chain_state
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        
        self.tx1_json = json.dumps({
            "sender_pubkey": "a"*96, 
            "recipient": "b", 
            "amount": 10, 
            "operations": {"1": []},
            "sequence_number": 0,
            "fee_limit": "0",
            "signature": "sig"
        })
        self.tx2_json = json.dumps({
            "sender_pubkey": "c"*96, 
            "recipient": "d", 
            "amount": 20, 
            "operations": {"1": []},
            "sequence_number": 0,
            "fee_limit": "0",
            "signature": "sig"
        })

        # Mock Tau Manager for createblock
        self.tau_patcher = unittest.mock.patch('commands.createblock.tau_manager')
        self.mock_tau = self.tau_patcher.start()
        self.mock_tau.tau_ready.is_set.return_value = True
        self.mock_tau.communicate_with_tau.return_value = "100" # Dummy return for validate
        
        # Mock Signature Validation
        self.sig_patcher = unittest.mock.patch('commands.createblock._validate_signature', return_value=True)
        self.sig_patcher.start()
        
        # Mock Pubkey Validation (if createblock calls it, or if it's in sendtx but createblock assumes valid?)
        # createblock does basic checks.

    def tearDown(self):
        """Clean up the temporary database."""
        self.tau_patcher.stop()
        self.sig_patcher.stop()
        clear_mempool()
        # Close the connection if it's open, to release file lock on Windows
        if hasattr(createblock.db, '_db_conn') and createblock.db._db_conn is not None:
            createblock.db._db_conn.close()
            createblock.db._db_conn = None
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        # Restore original db path if needed elsewhere
        config.set_database_path(config.DEFAULT_PROD_DB_PATH)

    def test_genesis_block_creation(self):
        """Test creating the first block (genesis block) from the mempool."""
        # Add transactions to mempool
        add_mempool_tx(self.tx1_json, "tx_hash_1", 1000)
        
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
        add_mempool_tx(self.tx1_json, "tx_hash_1", 1000)
        genesis_block_data = createblock.create_block_from_mempool()
        genesis_hash = genesis_block_data['block_hash']
        
        # 2. Add new tx and create the next block
        add_mempool_tx(self.tx2_json, "tx_hash_2", 2000)
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
