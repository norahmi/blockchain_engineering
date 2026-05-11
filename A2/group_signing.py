"""
Lab 2: Coordinated Group Signing over IPv8

Usage:
    python lab2_group_signing.py --role coordinator --key my_key.pem \\
        --peer2 <hex_pubkey> --peer3 <hex_pubkey> --port 8090

    python lab2_group_signing.py --role member --key my_key.pem --port 8091

Options:
    --role        'coordinator' or 'member'
    --key         Path to your .pem key file (same one used in Lab 1)
    --peer2       Hex public key of member 2 (coordinator only)
    --peer3       Hex public key of member 3 (coordinator only)
    --group-id    Resume with an existing group ID (skip registration)
    --port        UDP port to bind (default: 8090)
"""

import argparse
import asyncio
import logging
import os
import struct

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayloadWID
from ipv8.peer import Peer
from ipv8_service import IPv8

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────
COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")

SERVER_PUBLIC_KEY_HEX = (
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
)
SERVER_PUBLIC_KEY = bytes.fromhex(SERVER_PUBLIC_KEY_HEX)

# ──────────────────────────────────────────────
# Server-facing payloads (per spec)
# ──────────────────────────────────────────────

class RegisterGroupPayload(VariablePayloadWID):
    """msg_id=1  Register a group of 3 members."""
    msg_id = 1
    format_list = ["varlenH", "varlenH", "varlenH"]
    names = ["member1_key", "member2_key", "member3_key"]


class RegisterResponsePayload(VariablePayloadWID):
    """msg_id=2  Server reply to registration."""
    msg_id = 2
    format_list = ["?", "varlenHutf8", "varlenHutf8"]
    names = ["success", "group_id", "message"]


class ChallengeRequestPayload(VariablePayloadWID):
    """msg_id=3  Ask server for the current challenge."""
    msg_id = 3
    format_list = ["varlenHutf8"]
    names = ["group_id"]


class ChallengeResponsePayload(VariablePayloadWID):
    """msg_id=4  Server sends nonce + round metadata."""
    msg_id = 4
    format_list = ["varlenH", "q", "d"]
    names = ["nonce", "round_number", "deadline"]


class SignatureBundlePayload(VariablePayloadWID):
    """msg_id=5  Submit all 3 signatures for the current round."""
    msg_id = 5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]
    names = ["group_id", "round_number", "sig1", "sig2", "sig3"]


class RoundResultPayload(VariablePayloadWID):
    """msg_id=6  Server verdict on a submitted bundle."""
    msg_id = 6
    format_list = ["?", "q", "q", "varlenHutf8"]
    names = ["success", "round_number", "rounds_completed", "message"]


# ──────────────────────────────────────────────
# Internal peer-to-peer payloads
# ──────────────────────────────────────────────

class SignNoncePayload(VariablePayloadWID):
    """msg_id=10  Submitter broadcasts nonce to co-signers."""
    msg_id = 10
    format_list = ["varlenHutf8", "q", "varlenH"]
    names = ["group_id", "round_number", "nonce"]


class ShareSigPayload(VariablePayloadWID):
    """msg_id=11  Co-signer returns their signature to submitter."""
    msg_id = 11
    format_list = ["varlenHutf8", "q", "varlenH"]
    names = ["group_id", "round_number", "signature"]


# ──────────────────────────────────────────────
# Helper
# ──────────────────────────────────────────────

def load_or_create_key(path: str):
    from ipv8.keyvault.crypto import default_eccrypto
    if os.path.exists(path):
        print(f"[Key] Loading existing key from {path}")
        with open(path, "rb") as f:
            key = default_eccrypto.key_from_private_bin(f.read())
    else:
        print(f"[Key] Generating new key pair, saving to {path}")
        key = default_eccrypto.generate_key("curve25519")
        with open(path, "wb") as f:
            f.write(key.key_to_bin())
    print(f"[Key] Public key (hex): {key.pub().key_to_bin().hex()}")
    return key


def sign_nonce(crypto_key, nonce: bytes) -> bytes:
    """Sign a raw 32-byte nonce with the given private key."""
    from ipv8.keyvault.crypto import default_eccrypto
    return default_eccrypto.create_signature(crypto_key, nonce)


# ──────────────────────────────────────────────
# Community
# ──────────────────────────────────────────────

class Lab2Community(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)

        # Server-facing message handlers
        self.add_message_handler(RegisterResponsePayload, self.on_register_response)
        self.add_message_handler(ChallengeResponsePayload, self.on_challenge_response)
        self.add_message_handler(RoundResultPayload, self.on_round_result)

        # Peer-to-peer message handlers
        self.add_message_handler(SignNoncePayload, self.on_sign_nonce)
        self.add_message_handler(ShareSigPayload, self.on_share_sig)

        # Configuration (set via configure())
        self._role: str = "member"          # 'coordinator' or 'member'
        self._my_key = None                 # raw crypto key object
        self._my_pubkey_bin: bytes = b""    # serialised public key

        # Group info
        self._peer2_pubkey: bytes = b""
        self._peer3_pubkey: bytes = b""
        self._group_id: str = ""
        self._member_order: list[bytes] = []   # [key1, key2, key3] in registration order
        self._my_index: int = -1               # 0-based index in member_order

        # Round-robin submitter assignment: round 1 -> index 0, round 2 -> index 1, ...
        # The coordinator is always index 0.

        # State
        self._server_peer: Peer | None = None
        self._registered = asyncio.Event()
        self._done = asyncio.Event()

        # Per-round state (reset each round)
        self._current_round: int = 0
        self._current_nonce: bytes = b""
        self._collected_sigs: dict[int, bytes] = {}  # member_index -> signature
        self._sig_event = asyncio.Event()

    # ── public API ──────────────────────────────

    def configure(
        self,
        role: str,
        my_key,
        peer2_pubkey_hex: str = "",
        peer3_pubkey_hex: str = "",
        existing_group_id: str = "",
    ) -> None:
        self._role = role
        self._my_key = my_key
        self._my_pubkey_bin = my_key.pub().key_to_bin()

        if role == "coordinator":
            p2 = bytes.fromhex(peer2_pubkey_hex)
            p3 = bytes.fromhex(peer3_pubkey_hex)
            self._peer2_pubkey = p2
            self._peer3_pubkey = p3
            # Registration order: coordinator first
            self._member_order = [self._my_pubkey_bin, p2, p3]
            self._my_index = 0
            self._group_id = existing_group_id

    def started(self) -> None:
        self.register_task("find_server", self._find_server, interval=1.0, delay=0.5)

    # ── server discovery ─────────────────────────

    def _find_server(self) -> None:
        if self._server_peer is not None:
            return
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                self._server_peer = peer
                print(f"[IPv8] Found server at {peer.address}")
                self.cancel_pending_task("find_server")
                asyncio.ensure_future(self._main_flow())
                return
        print(f"[IPv8] Searching for server... ({len(self.get_peers())} peers known)")

    # ── main orchestration ───────────────────────

    async def _main_flow(self) -> None:
        if self._role == "coordinator":
            await self._coordinator_flow()
        else:
            # Members just sit and respond to incoming SignNonce / ShareSig messages.
            print("[Member] Ready, waiting for nonce broadcasts from submitter...")
            await self._done.wait()

    async def _coordinator_flow(self) -> None:
        # Step 1: register (or reuse existing group)
        if not self._group_id:
            await self._register_group()
        else:
            print(f"[Coordinator] Reusing existing group_id: {self._group_id}")
            self._registered.set()

        await self._registered.wait()
        if not self._group_id:
            print("[Coordinator] Registration failed, aborting.")
            self._done.set()
            return

        # Step 2: find teammates as IPv8 peers
        await self._wait_for_team_peers()

        # Step 3: execute 3 rounds
        for round_num in range(1, 4):
            submitter_index = round_num - 1   # round 1 → member0, round 2 → member1, …
            await self._run_round(round_num, submitter_index)
            if self._done.is_set():
                break

    # ── registration ─────────────────────────────

    async def _register_group(self) -> None:
        print("[Coordinator] Registering group with server...")
        payload = RegisterGroupPayload(
            member1_key=self._member_order[0],
            member2_key=self._member_order[1],
            member3_key=self._member_order[2],
        )
        self.ez_send(self._server_peer, payload)
        # Response handled in on_register_response

    @lazy_wrapper(RegisterResponsePayload)
    def on_register_response(self, peer: Peer, payload: RegisterResponsePayload) -> None:
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        print(f"[Server] Register response: success={payload.success}, "
                f"group_id={payload.group_id!r}, message={payload.message!r}")
        if payload.success:
            self._group_id = payload.group_id
            self._registered.set()
        else:
            print("[ERROR] Registration failed:", payload.message)
            self._registered.set()   # unblock flow so it can exit cleanly

    # ── team discovery ───────────────────────────

    async def _wait_for_team_peers(self) -> None:
        """Block until both teammates are visible as IPv8 peers."""
        print("[Coordinator] Waiting for teammate peers...")
        target_keys = {self._peer2_pubkey, self._peer3_pubkey}
        while True:
            found = {
                p.public_key.key_to_bin()
                for p in self.get_peers()
                if p.public_key.key_to_bin() in target_keys
            }
            if found == target_keys:
                print("[Coordinator] Both teammates found!")
                return
            await asyncio.sleep(0.2)

    def _get_peer_by_pubkey(self, pubkey_bin: bytes) -> Peer | None:
        for p in self.get_peers():
            if p.public_key.key_to_bin() == pubkey_bin:
                return p
        return None

    # ── round execution ──────────────────────────

    async def _run_round(self, round_num: int, submitter_index: int) -> None:
        """Execute one complete round."""
        self._current_round = round_num
        self._collected_sigs = {}
        self._sig_event.clear()

        submitter_key = self._member_order[submitter_index]
        is_submitter = (submitter_key == self._my_pubkey_bin)

        print(f"\n[Round {round_num}] Submitter: member{submitter_index + 1} "
                f"({'me' if is_submitter else 'peer'})")

        if is_submitter:
            await self._run_as_submitter(round_num)
        else:
            # Tell the actual submitter to request the challenge.
            # But: in the round-robin design the submitter is a co-member who
            # will receive a SignNonce broadcast and send their sig back.
            # The coordinator must instruct non-coordinator submitters.
            # Simplest: coordinator requests the challenge on their behalf
            # is NOT allowed (wrong IPv8 sender key).
            # So instead, we broadcast a "please request the challenge" trigger
            # to the designated submitter using a lightweight custom message.
            # For simplicity and speed, we use msg 10 with nonce=b"" as a trigger.
            submitter_peer = self._get_peer_by_pubkey(submitter_key)
            if submitter_peer is None:
                print(f"[ERROR] Cannot find submitter peer for round {round_num}")
                return

            # Signal submitter to take over this round via an empty SignNonce
            trigger = SignNoncePayload(
                group_id=self._group_id,
                round_number=round_num,
                nonce=b"",   # empty = "you are the submitter, please request"
            )
            self.ez_send(submitter_peer, trigger)
            print(f"[Round {round_num}] Signalled peer to act as submitter.")

            # Wait for this round to complete (sig_event fires in on_round_result)
            await asyncio.wait_for(self._sig_event.wait(), timeout=9.0)

    async def _run_as_submitter(self, round_num: int) -> None:
        """Request challenge, broadcast nonce, collect sigs, submit bundle."""
        # 1. Request challenge
        print(f"[Round {round_num}] Requesting challenge from server...")
        req = ChallengeRequestPayload(group_id=self._group_id)
        self.ez_send(self._server_peer, req)
        # ChallengeResponse is handled in on_challenge_response which will:
        #   - store nonce
        #   - broadcast to teammates
        #   - sign own nonce
        # We just wait for _sig_event to fire (set when bundle is accepted)
        await asyncio.wait_for(self._sig_event.wait(), timeout=9.5)

    @lazy_wrapper(ChallengeResponsePayload)
    def on_challenge_response(self, peer: Peer, payload: ChallengeResponsePayload) -> None:
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        print(f"[Server] Challenge round={payload.round_number}, "
                f"nonce={payload.nonce.hex()[:16]}..., deadline={payload.deadline:.2f}")

        self._current_nonce = payload.nonce
        self._current_round = payload.round_number

        # Sign immediately
        my_sig = sign_nonce(self._my_key, payload.nonce)
        self._collected_sigs[self._my_index] = my_sig
        print(f"[Round {payload.round_number}] Signed nonce (index {self._my_index})")

        # Broadcast nonce to all teammates
        asyncio.ensure_future(self._broadcast_nonce(payload.round_number, payload.nonce))

    async def _broadcast_nonce(self, round_num: int, nonce: bytes) -> None:
        """Send SignNonce to all other members."""
        msg = SignNoncePayload(
            group_id=self._group_id,
            round_number=round_num,
            nonce=nonce,
        )
        for key in self._member_order:
            if key == self._my_pubkey_bin:
                continue
            peer = self._get_peer_by_pubkey(key)
            if peer:
                self.ez_send(peer, msg)
        print(f"[Round {round_num}] Broadcasted nonce to teammates.")
        # Now wait for sigs to arrive (on_share_sig will call _try_submit)
        await self._wait_and_submit(round_num, nonce)

    async def _wait_and_submit(self, round_num: int, nonce: bytes) -> None:
        """Poll until all 3 sigs collected, then submit."""
        for _ in range(90):   # up to ~4.5s of polling
            if len(self._collected_sigs) == 3:
                break
            await asyncio.sleep(0.05)

        if len(self._collected_sigs) < 3:
            print(f"[WARN] Round {round_num}: only {len(self._collected_sigs)} sigs collected, submitting anyway")

        sigs = [self._collected_sigs.get(i, b"\x00" * 64) for i in range(3)]
        bundle = SignatureBundlePayload(
            group_id=self._group_id,
            round_number=round_num,
            sig1=sigs[0],
            sig2=sigs[1],
            sig3=sigs[2],
        )
        print(f"[Round {round_num}] Submitting bundle to server...")
        self.ez_send(self._server_peer, bundle)

    # ── peer message handlers ────────────────────

    @lazy_wrapper(SignNoncePayload)
    def on_sign_nonce(self, peer: Peer, payload: SignNoncePayload) -> None:
        """Received a nonce broadcast (or a round-start trigger if nonce is empty)."""
        # Validate sender is a known group member
        sender_key = peer.public_key.key_to_bin()
        if sender_key not in self._member_order:
            print(f"[WARN] SignNonce from unknown peer {sender_key.hex()[:16]}, ignoring")
            return

        # Empty nonce = trigger: we are the designated submitter for this round
        if payload.nonce == b"":
            print(f"[Round {payload.round_number}] Triggered as submitter by coordinator")
            # Update our local group_id in case we didn't have it yet
            self._group_id = payload.group_id
            self._current_round = payload.round_number
            self._collected_sigs = {}
            self._sig_event.clear()
            asyncio.ensure_future(self._run_as_submitter(payload.round_number))
            return

        # Normal case: received a real nonce to sign
        print(f"[Round {payload.round_number}] Received nonce, signing...")
        self._current_nonce = payload.nonce
        self._current_round = payload.round_number
        self._group_id = payload.group_id

        my_sig = sign_nonce(self._my_key, payload.nonce)

        # Send sig back to the submitter (the sender of the nonce broadcast)
        reply = ShareSigPayload(
            group_id=payload.group_id,
            round_number=payload.round_number,
            signature=my_sig,
        )
        self.ez_send(peer, reply)
        print(f"[Round {payload.round_number}] Sent signature back to submitter.")

    @lazy_wrapper(ShareSigPayload)
    def on_share_sig(self, peer: Peer, payload: ShareSigPayload) -> None:
        """Received a co-signer's signature."""
        sender_key = peer.public_key.key_to_bin()
        try:
            sender_index = self._member_order.index(sender_key)
        except ValueError:
            print(f"[WARN] ShareSig from unknown peer, ignoring")
            return

        print(f"[Round {payload.round_number}] Got sig from member{sender_index + 1}")
        self._collected_sigs[sender_index] = payload.signature

    @lazy_wrapper(RoundResultPayload)
    def on_round_result(self, peer: Peer, payload: RoundResultPayload) -> None:
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        status = "✓" if payload.success else "✗"
        print(f"\n[Server] {status} Round {payload.round_number}: {payload.message} "
                f"(completed: {payload.rounds_completed}/3)")

        if payload.success:
            self._sig_event.set()  # unblock current round
            if payload.rounds_completed == 3:
                print("\n🎉  All 3 rounds completed successfully!")
                self._done.set()
        else:
            # On rejection (wrong sig, wrong submitter, etc.) let the timeout
            # handle recovery; log clearly for debugging.
            print(f"[ERROR] Server rejected bundle: {payload.message}")
            # If it's a fixable error (bad sig), still unblock so coordinator
            # can move on (the budget is still live).
            if "budget exceeded" in payload.message or "group already completed" in payload.message:
                self._done.set()


# ──────────────────────────────────────────────
# Bootstrap & run
# ──────────────────────────────────────────────

async def run(
    role: str,
    key_path: str,
    peer2_hex: str = "",
    peer3_hex: str = "",
    group_id: str = "",
    port: int = 8090,
) -> None:
    my_key = load_or_create_key(key_path)

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.add_key("my peer", "curve25519", key_path)
    builder.add_overlay(
        "Lab2Community",
        "my peer",
        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [("started",)],
    )
    config = builder.finalize()

    for iface in config.get("interfaces", []):
        iface["ip"] = "0.0.0.0"
        iface["port"] = port

    ipv8 = IPv8(config, extra_communities={"Lab2Community": Lab2Community})
    await ipv8.start()
    print(f"[IPv8] Started on 0.0.0.0:{port} as '{role}'")

    community: Lab2Community = ipv8.get_overlay(Lab2Community)
    community._member_order = []  # will be set in configure for coordinator; members infer from msgs

    community.configure(
        role=role,
        my_key=my_key,
        peer2_pubkey_hex=peer2_hex,
        peer3_pubkey_hex=peer3_hex,
        existing_group_id=group_id,
    )

    # For members we also need to set _my_index once we know the order.
    # Members learn the order when they receive the first SignNonce with a real nonce;
    # but they need their index to reply properly. We pre-set it from the key.
    # The coordinator will include _member_order in the trigger; members discover it lazily.
    # For now, members discover their index in on_share_sig / on_sign_nonce via their own key.
    # (The community already stores self._my_pubkey_bin.)

    try:
        await asyncio.wait_for(community._done.wait(), timeout=120)
    except asyncio.TimeoutError:
        print("\n[TIMEOUT] Did not complete within 2 minutes.")
    finally:
        await ipv8.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Lab 2: Coordinated Group Signing")
    parser.add_argument("--role", required=True, choices=["coordinator", "member"],
                        help="'coordinator' (member1) or 'member' (member2/3)")
    parser.add_argument("--key", default="my_key.pem",
                        help="Path to .pem key file (same as Lab 1)")
    parser.add_argument("--peer2", default="",
                        help="Hex public key of member 2 (coordinator only)")
    parser.add_argument("--peer3", default="",
                        help="Hex public key of member 3 (coordinator only)")
    parser.add_argument("--group-id", default="",
                        help="Resume with an existing group ID (skip registration)")
    parser.add_argument("--port", type=int, default=8090,
                        help="UDP port to bind (default: 8090)")
    args = parser.parse_args()

    if args.role == "coordinator" and (not args.peer2 or not args.peer3):
        parser.error("Coordinator requires --peer2 and --peer3 (hex public keys of teammates)")

    logging.basicConfig(level=logging.WARNING)
    asyncio.run(run(
        role=args.role,
        key_path=args.key,
        peer2_hex=args.peer2,
        peer3_hex=args.peer3,
        group_id=args.group_id,
        port=args.port,
    ))


if __name__ == "__main__":
    main()
