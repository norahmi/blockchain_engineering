# Blockchain Engineering

## Team Members

1. Norah Elisabeth Milanesi (n.e.milanesi@student.tudelft.nl)
2. Marco Trapasso (m.trapasso-1@student.tudelft.nl)

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
python client.py --role member1 --key member1.pem \
  --member1 <key1_hex> --member2 <key2_hex> --member3 <key3_hex>

# member2 (waits for messages)
python client.py --role member2 --key member2.pem \
  --member1 <key1_hex> --member2 <key2_hex> --member3 <key3_hex>

# member3 (waits for messages)
python client.py --role member3 --key member3.pem \
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

##### Message types

| Message | Direction | Purpose |
|---------|-----------|---------|
| `GroupRegistration` | → Server | Register the 3 member keys as a group |
| `RegistrationAnswer` | ← Server | Confirms registration and returns `group_id` |
| `AskChallenge` | → Server | Request a nonce for the current round |
| `Challenge` | ← Server | Returns nonce + deadline |
| `Bundle` | → Server | Submit all 3 signatures |
| `Verdict` | ← Server | Pass/fail result for the round |
| `PeerRound` | ↔ Peers | Request a signature (or wake the next submitter) |
| `PeerSignature` | ↔ Peers | Return a signed nonce |