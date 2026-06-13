# Blockchain Engineering

## Team Members

1. Norah Elisabeth Milanesi (n.e.milanesi@student.tudelft.nl)
2. Marco Trapasso (m.trapasso-1@student.tudelft.nl)
3. Jhon Doe (fake member)

## Project Structure

### A1 - Lab 1
This folder contains the solution of lab 1.

### A2 - Lab 2
This folder contains the solution for lab 2.

A peer-to-peer protocol where a team of **3 members** collaboratively sign challenges issued by a central server, across **3 sequential rounds**.

#### How it works

##### Roles

Each member is assigned a fixed slot (**member1**, **member2**, **member3**). The slot determines who acts as **submitter** in each round:

| Round | Submitter |
|-------|-----------|
| 1     | member1   |
| 2     | member2   |
| 3     | member3   |

##### Each round (from the submitter's perspective)

1. **Request a challenge** – The submitter asks the server for a nonce (a 32-byte random value) with an associated deadline.
2. **Collect signatures** – The submitter broadcasts the nonce to the other two members via P2P messages. Each member signs the nonce with their private key and sends it back.
3. **Submit a bundle** – Once all 3 signatures are collected, the submitter sends them to the server as a `Bundle`.
4. **Receive a verdict** – The server validates all signatures and replies with a success or failure verdict.
5. **Wake the next submitter** – On success, the current submitter pings the next member to kick off their round.

The protocol completes when all 3 rounds have been accepted by the server.

---

##### Running the client

Each team member runs the client with their own private key file and the public keys of all three members.

```bash
# member1 (starts the protocol)
python A2/group_signing.py --role member1 --key member1.pem \
  --member1 <key1_hex> --member2 <key2_hex> --member3 <key3_hex>

# member2 (waits for messages)
python A2/group_signing.py --role member2 --key member2.pem \
  --member1 <key1_hex> --member2 <key2_hex> --member3 <key3_hex>

# member3 (waits for messages)
python A2/group_signing.py --role member3 --key member3.pem \
  --member1 <key1_hex> --member2 <key2_hex> --member3 <key3_hex>
```

If your group already has a `group_id` from a previous run, pass `--group-id <id>` to skip re-registration.

##### Key flags

| Flag | Description |
|------|-------------|
| `--key` | Path to your private key file (required) |
| `--port` | UDP port to listen on (default: `8091`) |
| `--group-id` | Reuse an existing group registration |
| `--start` | Force this node to register and start round 1 |
| `--debug-peers` | Print peer discovery info while waiting |
| `--discovery-timeout` | Seconds to wait for peers/server (default: 300) |
| `--runtime` | Max total runtime in seconds (default: 300) |

# Lab 3: Proof-of-Work Blockchain over IPv8

This directory contains the implementation of a three-node Proof-of-Work blockchain for Lab 3. All three teammates run the same program, `A3/main.py`, with their own private key and role.

The nodes:

1. Register the group's blockchain community with the Lab 3 server.
2. Discover teammates through IPv8.
3. Validate and propagate transactions.
4. Mine and propagate blocks.
5. Synchronize their chains using the longest-chain rule.
6. Answer the server's chain-height and block queries.

## Group Configuration

The configuration used by this group is:

```text
Group ID:      d92d3dd3fb7cf61e
Community ID:  7f2c8a9d4b1e6f3058d0c3a4179b2e6c0f84a1d9
```

The canonical member order is:

```text
member1:
4c69624e61434c504b3a1355b0bd3e6b963f45379eee889b1f2592802773e7a8fbcb7f2ce60923867b0d01f84ff1e8c86c59407be67563555c544c3021fea152f009567e562a7cf99dcb

member2:
4c69624e61434c504b3a7c06b4f14e578b46e425ad5991705dee61b5e8de71f6b6e3b2d78ef4c67a5b04b3f84eec1477d29741045afec581cff2bd3686cdd758dee3fd854b4670e27085

member3:
4c69624e61434c504b3aa1d29954ff1486c00d57287b1144a0abf3b3c6523c15013dd27ddbfccb60a23547511cb72369b1497846444763d623800148550a7d2929a03663d0ce91aae4c5
```

Every node must use this exact order. The order determines which member mines
each block height.

## Architecture

The program runs two IPv8 communities with the same Lab 1/Lab 2 identity key.

### Registration Community

`RegistrationCommunity` uses the fixed community ID published by the course:

```text
4c616233426c6f636b636861696e323032365057
```

It discovers the server, verifies that the peer's public key matches the published Lab 3 server key, and sends:

| ID | Payload | Purpose |
|---:|---|---|
| 1 | `RegisterBlockchain` | Register the group ID and blockchain community ID |
| 2 | `RegisterResponse` | Receive the server's registration result |

The registration request is retried until an authenticated successful response is received.

### Blockchain Community

`BlockchainCommunity` uses the group's chosen 20-byte community ID. It stores:

- all known connected blocks;
- the current canonical chain;
- blocks whose parents are still missing;
- verified transaction objects;
- the mempool;
- transaction hashes confirmed by the canonical chain.

All communication uses IPv8 `ez_send`, so packets are authenticated and signed. Server requests are accepted only from the published server public key. Peer synchronization messages are accepted only from one of the three configured member public keys.

## Server Protocol

The blockchain community implements the six assignment messages exactly:

| ID | Payload | Direction |
|---:|---|---|
| 1 | `SubmitTransaction` | Server or teammate to node |
| 2 | `SubmitTransactionResponse` | Node to sender |
| 3 | `GetChainHeight` | Server or teammate to node |
| 4 | `ChainHeightResponse` | Node to requester |
| 5 | `GetBlock` | Server or teammate to node |
| 6 | `BlockResponse` | Node to requester |

Message ID `10`, `PeerBlock`, is an internal authenticated message used to announce blocks to teammates. It contains the same block fields as `BlockResponse`.

## Transactions

A `Transaction` contains:

```text
sender_key
data
timestamp
signature
```

The signed bytes are:

```text
sender_key || data || timestamp_as_8_byte_big_endian_integer
```

The sender public key is decoded with `default_eccrypto.key_from_public_bin()`. The signature is then checked with `default_eccrypto.is_valid_signature()`.

The transaction hash is:

```text
SHA256(sender_key || data || timestamp_8byte_be || signature)
```

Valid transactions are added to the mempool and broadcast to teammates. Transactions remain available for rebroadcast until they appear in the canonical chain.

## Block Format

The `Block` class represents a block and constructs the required 84-byte header:

```text
prev_hash  : 32 bytes
txs_hash   : 32 bytes
timestamp  :  8 bytes, uint64 big-endian
difficulty :  4 bytes, uint32 big-endian
nonce      :  8 bytes, uint64 big-endian
```

The block hash is:

```text
SHA256(header)
```

The body commitment is:

```text
SHA256(tx_hash_1 || tx_hash_2 || ... || tx_hash_n)
```

For an empty block:

```text
txs_hash = SHA256(b"")
```

`Block.validate_self()` checks field lengths, the body commitment, header encoding, and the declared Proof-of-Work difficulty.

## Genesis Block

Every node creates the same deterministic block at height zero:

```text
height      = 0
prev_hash   = 32 zero bytes
txs_hash    = SHA256(b"")
timestamp   = 0
difficulty  = 0
nonce       = 0
transactions = empty
```

Its hash is:

```text
7dcab14b103678006245c4396b91127cd6f1b57a7240d3cbde13aa1ebd48aa3b
```

Using a fixed genesis block ensures that all three chains start identically.

## Mining

The default difficulty is eight leading zero bits. Mining tries nonces from zero upward until:

```text
leading_zero_bits(SHA256(header)) >= difficulty
```

The miner periodically yields to the asyncio event loop and stops its current search if the canonical tip changes.

To reduce simultaneous forks, mining is assigned in round-robin order:

```text
height 1 -> member1
height 2 -> member2
height 3 -> member3
height 4 -> member1
...
```

The miner selection formula is:

```python
miner_index = (next_height - 1) % 3
```

Empty blocks continue to be mined after a transaction is included. These blocks provide the three confirmations required by the server.

## Consensus and Synchronization

When a block arrives, the node checks:

1. The block hash matches its header.
2. The Proof-of-Work satisfies the declared difficulty.
3. `txs_hash` matches the concatenated transaction hashes.
4. The parent exists and has height `block.height - 1`.
5. `prev_hash` identifies that parent.

A block with a missing parent is temporarily stored as an orphan. The node then requests missing heights from its teammates.

The canonical tip selection is:

1. Prefer the chain with the greater height.
2. At equal height, prefer the lower block hash as a deterministic tie-break.

After a chain switch, confirmed transaction hashes are rebuilt and transactions from known non-canonical blocks are returned to the mempool when appropriate.

Every two seconds, a node:

- requests teammate chain heights;
- rebroadcasts pending transactions;
- announces its current tip.

If a teammate reports a greater height, the missing blocks are requested with `GetBlock`.

## Running the Nodes

Install the project dependencies first:

```bash
python3 -m pip install -r A1/marco/requirements.txt
```

Run commands from the repository root.

### Member 1

```bash
python3 A3/main.py \
  --role member1 \
  --key-file <member2-private-key-file> \
  --group-id d92d3dd3fb7cf61e \
  --community-id 7f2c8a9d4b1e6f3058d0c3a4179b2e6c0f84a1d9 \
  --member1 4c69624e61434c504b3a1355b0bd3e6b963f45379eee889b1f2592802773e7a8fbcb7f2ce60923867b0d01f84ff1e8c86c59407be67563555c544c3021fea152f009567e562a7cf99dcb \
  --member2 4c69624e61434c504b3a7c06b4f14e578b46e425ad5991705dee61b5e8de71f6b6e3b2d78ef4c67a5b04b3f84eec1477d29741045afec581cff2bd3686cdd758dee3fd854b4670e27085 \
  --member3 4c69624e61434c504b3aa1d29954ff1486c00d57287b1144a0abf3b3c6523c15013dd27ddbfccb60a23547511cb72369b1497846444763d623800148550a7d2929a03663d0ce91aae4c5
```

### Member 2

Member 2 runs the same command with their own key file:

```bash
python3 A3/main.py \
  --role member2 \
  --key-file <member2-private-key-file> \
  --group-id d92d3dd3fb7cf61e \
  --community-id 7f2c8a9d4b1e6f3058d0c3a4179b2e6c0f84a1d9 \
  --member1 4c69624e61434c504b3a1355b0bd3e6b963f45379eee889b1f2592802773e7a8fbcb7f2ce60923867b0d01f84ff1e8c86c59407be67563555c544c3021fea152f009567e562a7cf99dcb \
  --member2 4c69624e61434c504b3a7c06b4f14e578b46e425ad5991705dee61b5e8de71f6b6e3b2d78ef4c67a5b04b3f84eec1477d29741045afec581cff2bd3686cdd758dee3fd854b4670e27085 \
  --member3 4c69624e61434c504b3aa1d29954ff1486c00d57287b1144a0abf3b3c6523c15013dd27ddbfccb60a23547511cb72369b1497846444763d623800148550a7d2929a03663d0ce91aae4c5
```

### Member 3

Member 3 also uses the same member order:

```bash
python3 A3/main.py \
  --role member3 \
  --key-file <member3-private-key-file> \
  --group-id d92d3dd3fb7cf61e \
  --community-id 7f2c8a9d4b1e6f3058d0c3a4179b2e6c0f84a1d9 \
  --member1 4c69624e61434c504b3a1355b0bd3e6b963f45379eee889b1f2592802773e7a8fbcb7f2ce60923867b0d01f84ff1e8c86c59407be67563555c544c3021fea152f009567e562a7cf99dcb \
  --member2 4c69624e61434c504b3a7c06b4f14e578b46e425ad5991705dee61b5e8de71f6b6e3b2d78ef4c67a5b04b3f84eec1477d29741045afec581cff2bd3686cdd758dee3fd854b4670e27085 \
  --member3 4c69624e61434c504b3aa1d29954ff1486c00d57287b1144a0abf3b3c6523c15013dd27ddbfccb60a23547511cb72369b1497846444763d623800148550a7d2929a03663d0ce91aae4c5
```

Only public keys are shared between teammates. Every private key remains on its
owner's machine.

## Important Command-Line Options

| Option | Description |
|---|---|
| `--role` | Member position used by the round-robin mining schedule |
| `--key-file` | The node owner's Lab 1/Lab 2 private key |
| `--key-type` | Key generation type if the key file does not already exist |
| `--group-id` | Group ID assigned during Lab 2 |
| `--community-id` | Shared 20-byte blockchain community ID |
| `--member1/2/3` | Canonical public-key order |
| `--difficulty` | Leading-zero-bit difficulty, default `8` |
| `--block-interval` | Delay before mining after a new tip, default `1.0` second |
| `--max-txs-per-block` | Maximum mempool transactions selected per block |
| `--no-register` | Start without registering with the Lab 3 server |
| `--runtime` | Stop after a number of seconds; `0` means run indefinitely |
| `--debug-peers` | Periodically print visible IPv8 peers |

If `--community-id` is omitted, the program derives a deterministic 20-byte ID from the group ID and the ordered member public keys. Passing the explicit shared ID is safer because it avoids differences caused by inconsistent key ordering.