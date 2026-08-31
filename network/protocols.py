# Protocol ID constants for Tau networking

TAU_PROTOCOL_HANDSHAKE = "/tau/handshake/2.0.0"
TAU_PROTOCOL_PING = "/tau/ping/2.0.0"
TAU_PROTOCOL_SYNC = "/tau/sync/2.0.0"
TAU_PROTOCOL_BLOCKS = "/tau/blocks/2.0.0"
TAU_PROTOCOL_TX = "/tau/tx/2.0.0"
TAU_PROTOCOL_GOSSIP = "/tau/gossip/2.0.0"
TAU_PROTOCOL_DHT = "/tau/dht/2.0.0"

# Gossipsub topics
TAU_GOSSIP_TOPIC_BLOCKS = "tau/blocks/2.0.0"
TAU_GOSSIP_TOPIC_TRANSACTIONS = "tau/transactions/2.0.0"
TAU_GOSSIP_TOPIC_GOVERNANCE = "tau/governance/2.0.0"
# Rule sharing rides its own topic so a flood of large rule offers cannot crowd
# out coin-transfer gossip on tau/transactions.
TAU_GOSSIP_TOPIC_RULES = "tau/rules/2.0.0"
# Co-signature approvals ride their own topic for the same reason rule sharing
# does: a burst of parked requests must not crowd out coin-transfer gossip, and
# a vote is time-sensitive -- it is what releases someone's funds.
TAU_GOSSIP_TOPIC_APPROVALS = "tau/approvals/1.0.0"
TAU_GOSSIP_TOPIC_PEERS = "tau/peers/2.0.0"

# Mempool & Edge Ingestion Limits
TAU_GOSSIP_MAX_RAW_TX_BYTES = 262144
TAU_MAX_USER_TX_BYTES = 8192
TAU_MAX_GOVERNANCE_VOTE_BYTES = 8192
TAU_MAX_GOVERNANCE_UPDATE_BYTES = 262144
# Rule offers carry up to MAX_OFFER_RULE_BYTES (8 KiB) of Tau text plus the
# envelope, and an accept repeats that text; the reject carries only an id.
TAU_MAX_RULE_OFFER_BYTES = 24576
TAU_MAX_RULE_OFFER_ACCEPT_BYTES = 24576
TAU_MAX_RULE_OFFER_REJECT_BYTES = 8192
TAU_MEMPOOL_SNAPSHOT_MAX_TOTAL = 200
TAU_MEMPOOL_SNAPSHOT_MAX_UPDATES = 32
TAU_MEMPOOL_SNAPSHOT_MAX_VOTES = 64
# Sub-quota so a backlog of rule transactions cannot become the entire snapshot
# a peer receives on connect.
TAU_MEMPOOL_SNAPSHOT_MAX_RULE_TXS = 32
# A request carries a recipient, an amount, an approver map and up to 8 custom
# inputs of 256 bytes; a vote carries an id, a bool and a short reason.
TAU_MAX_APPROVAL_REQUEST_BYTES = 8192
TAU_MAX_TRANSFER_VOTE_BYTES = 4096
# Same reasoning as the rule sub-quota: a backlog of parked requests must not
# become the entire snapshot a peer receives on connect.
TAU_MEMPOOL_SNAPSHOT_MAX_APPROVAL_TXS = 32
