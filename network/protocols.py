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
# Retractable transfers get their own topic: parks are floods, while a retract
# is deadline-sensitive and must not queue behind them.
TAU_GOSSIP_TOPIC_RETRACTABLE = "tau/retractable/1.0.0"
# Standing payments get their own topic too: creates can arrive in bursts, and a
# cancel is time-sensitive -- it must land before the next due point.
TAU_GOSSIP_TOPIC_STANDING = "tau/standing/1.0.0"
# Payout rules: installs carry rule text, executions are what moves the money.
TAU_GOSSIP_TOPIC_PAYOUT = "tau/payout/1.0.0"
# Receive routes: small, rare, and a release by a destination is time-sensitive.
TAU_GOSSIP_TOPIC_ROUTES = "tau/routes/1.0.0"
# Envelopes: a spend is an everyday payment, and a release by
# the sender should not wait behind a burst of sends.
TAU_GOSSIP_TOPIC_ENVELOPES = "tau/envelopes/1.0.0"
TAU_GOSSIP_TOPIC_PEERS = "tau/peers/2.0.0"

# Mempool & Edge Ingestion Limits
TAU_GOSSIP_MAX_RAW_TX_BYTES = 262144
# A tx or gossip request carries one payload as a JSON string. JSON escapes can
# double its size, and the envelope adds a little more.
TAU_STREAM_REQUEST_MAX_BYTES = 4 * TAU_GOSSIP_MAX_RAW_TX_BYTES
# A tx or gossip request is one write of at most 1 MiB, so it arrives in seconds.
REQUEST_READ_TIMEOUT = 30.0
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
# A park and a retract each carry a few pubkeys, an amount and a signature.
TAU_MAX_RETRACTABLE_TRANSFER_BYTES = 4096
TAU_MAX_RETRACT_TRANSFER_BYTES = 4096
TAU_MEMPOOL_SNAPSHOT_MAX_RETRACTABLE_TXS = 32
# A create carries two pubkeys and a few integers, an update the same plus the
# id it replaces; a cancel and an execute carry one id.
TAU_MAX_STANDING_PAYMENT_CREATE_BYTES = 4096
TAU_MAX_STANDING_PAYMENT_UPDATE_BYTES = 4096
TAU_MAX_STANDING_PAYMENT_CANCEL_BYTES = 4096
TAU_MAX_STANDING_PAYMENT_EXECUTE_BYTES = 4096
TAU_MEMPOOL_SNAPSHOT_MAX_STANDING_TXS = 32
# A rule set carries up to 4 KiB of Tau text and eight slots; an execution an id,
# up to eight recipients and eight data values; a revoke the envelope.
TAU_MAX_PAYOUT_RULE_SET_BYTES = 16384
TAU_MAX_PAYOUT_EXECUTE_BYTES = 8192
TAU_MAX_PAYOUT_RULE_REVOKE_BYTES = 4096
TAU_MEMPOOL_SNAPSHOT_MAX_PAYOUT_TXS = 32
# A route set carries a destination and five numbers; remove and release less.
TAU_MAX_RECEIVE_ROUTE_SET_BYTES = 4096
TAU_MAX_RECEIVE_ROUTE_REMOVE_BYTES = 4096
TAU_MAX_RECEIVE_ROUTE_RELEASE_BYTES = 4096
TAU_MEMPOOL_SNAPSHOT_MAX_ROUTE_TXS = 32
# A send carries a recipient, an amount and at most twelve caps; spend and
# release less.
TAU_MAX_ENVELOPE_SEND_BYTES = 4096
TAU_MAX_ENVELOPE_SPEND_BYTES = 4096
TAU_MAX_ENVELOPE_RELEASE_BYTES = 4096
TAU_MEMPOOL_SNAPSHOT_MAX_ENVELOPE_TXS = 64
