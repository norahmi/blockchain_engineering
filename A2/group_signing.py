from __future__ import annotations

import argparse
import asyncio
import logging
import time
from pathlib import Path

from ipv8.community import Community
from ipv8.configuration import (
    ConfigBuilder,
    Strategy,
    WalkerDefinition,
    default_bootstrap_defs,
)
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayloadWID
from ipv8.peer import Peer
from ipv8_service import IPv8


LAB2_COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")
SERVER_KEY = bytes.fromhex(
    "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011"
    "a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
)

TEAM_SIZE = 3
FINAL_ROUND = 3
EMPTY_TRIGGER = b""


def out(line: str) -> None:
    print(line, flush=True)
    
def read_private_public_key(path: Path) -> bytes:
    if not path.exists():
        raise FileNotFoundError(
            f"{path} does not exist; use the same private key file that passed Lab 1"
        )
    with path.open("rb") as handle:
        return default_eccrypto.key_from_private_bin(handle.read()).pub().key_to_bin()


class GroupRegistration(VariablePayloadWID):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "varlenH"]
    names = ["member1_key", "member2_key", "member3_key"]


class RegistrationAnswer(VariablePayloadWID):
    msg_id = 2
    format_list = ["?", "varlenHutf8", "varlenHutf8"]
    names = ["success", "group_id", "message"]


class AskChallenge(VariablePayloadWID):
    msg_id = 3
    format_list = ["varlenHutf8"]
    names = ["group_id"]


class Challenge(VariablePayloadWID):
    msg_id = 4
    format_list = ["varlenH", "q", "d"]
    names = ["nonce", "round_number", "deadline"]


class Bundle(VariablePayloadWID):
    msg_id = 5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]
    names = ["group_id", "round_number", "sig1", "sig2", "sig3"]


class Verdict(VariablePayloadWID):
    msg_id = 6
    format_list = ["?", "q", "q", "varlenHutf8"]
    names = ["success", "round_number", "rounds_completed", "message"]


class PeerRound(VariablePayloadWID):
    """Shared teammate protocol: empty nonce starts submitter mode; 32 bytes asks for a signature."""

    msg_id = 10
    format_list = ["varlenHutf8", "q", "varlenH"]
    names = ["group_id", "round_number", "nonce"]


class PeerSignature(VariablePayloadWID):
    msg_id = 11
    format_list = ["varlenHutf8", "q", "varlenH"]
    names = ["group_id", "round_number", "signature"]


class TeammateOverlay(Community):
    community_id = LAB2_COMMUNITY_ID

    def __init__(self, settings) -> None:
        super().__init__(settings)

        self.add_message_handler(RegistrationAnswer, self.handle_registration)
        self.add_message_handler(Challenge, self.handle_challenge)
        self.add_message_handler(Verdict, self.handle_verdict)
        self.add_message_handler(PeerRound, self.handle_peer_round)
        self.add_message_handler(PeerSignature, self.handle_peer_signature)

        self.keys: tuple[bytes, bytes, bytes] | None = None
        self.slot = -1
        self.group_id = ""

        self.registered = asyncio.Event()
        self.registration_failed = ""

        self.challenge_events: dict[int, asyncio.Event] = {}
        self.verdict_events: dict[int, asyncio.Event] = {}
        self.nonces: dict[int, bytes] = {}
        self.deadlines: dict[int, float] = {}
        self.signatures: dict[int, dict[int, bytes]] = {}
        self.verdicts: dict[int, Verdict] = {}

        self.rounds_started: set[int] = set()
        self.rounds_touched: set[int] = set()
        self.finished = asyncio.Event()

    def install_group(self, keys: list[bytes], group_id: str) -> None:
        if len(keys) != TEAM_SIZE:
            raise ValueError("exactly 3 public keys are required")

        me = self.my_peer.public_key.key_to_bin()
        if me not in keys:
            raise ValueError("the selected private key is not listed as member1/member2/member3")

        self.keys = (keys[0], keys[1], keys[2])
        self.slot = keys.index(me)
        self.group_id = group_id

    def is_server(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin() == SERVER_KEY

    def is_team_peer(self, peer: Peer) -> bool:
        return self.keys is not None and peer.public_key.key_to_bin() in self.keys

    def lookup_peer(self, key: bytes) -> Peer | None:
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == key:
                return peer
        return None

    def current_server(self) -> Peer | None:
        for peer in self.get_peers():
            if self.is_server(peer):
                return peer
        return None

    async def wait_for_server(self, seconds: float) -> Peer:
        started = time.monotonic()
        while time.monotonic() - started < seconds:
            server = self.current_server()
            if server is not None:
                return server
            await asyncio.sleep(0.2)
        raise TimeoutError("server was not discovered")

    async def wait_for_full_team(self, seconds: float) -> None:
        assert self.keys is not None
        expected = {key for key in self.keys if key != self.my_peer.public_key.key_to_bin()}
        started = time.monotonic()

        while time.monotonic() - started < seconds:
            visible = {peer.public_key.key_to_bin() for peer in self.get_peers()} & expected
            if visible == expected:
                return
            await asyncio.sleep(0.2)

        raise TimeoutError(f"only found {len(visible)}/{len(expected)} teammate peers")

    async def register_or_reuse(self, timeout: float, interval: float) -> None:
        assert self.keys is not None
        if self.group_id:
            await self.wait_for_server(timeout)
            return

        server = await self.wait_for_server(timeout)
        request = GroupRegistration(*self.keys)
        started = time.monotonic()

        while not self.registered.is_set() and time.monotonic() - started < timeout:
            self.ez_send(server, request)
            try:
                await asyncio.wait_for(self.registered.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass

        if not self.registered.is_set():
            raise TimeoutError("registration did not receive a server response")
        if self.registration_failed:
            raise RuntimeError(self.registration_failed)

    async def submitter_round(self, round_number: int) -> None:
        assert self.keys is not None

        if round_number in self.rounds_started:
            return
        self.rounds_started.add(round_number)

        expected_slot = round_number - 1
        if self.slot != expected_slot:
            return

        self.rounds_touched.add(round_number)
        self.signatures[round_number] = {}
        self.challenge_events[round_number] = asyncio.Event()
        self.verdict_events[round_number] = asyncio.Event()

        out(f"[round {round_number}] I am submitter")
        await self.fetch_challenge(round_number)

        nonce = self.nonces.get(round_number, b"")
        if len(nonce) != 32:
            out(f"[round {round_number}] no usable nonce")
            return

        self.signatures[round_number][self.slot] = default_eccrypto.create_signature(self.my_peer.key, nonce)
        await self.gather_team_signatures(round_number, nonce)

        if len(self.signatures[round_number]) != TEAM_SIZE:
            out(f"[round {round_number}] cannot submit; missing signatures")
            return

        await self.send_bundle_until_verdict(round_number)

        verdict = self.verdicts.get(round_number)
        if verdict is None or not verdict.success:
            return
        if verdict.rounds_completed >= FINAL_ROUND:
            self.finished.set()
            return

        await self.poke_next_submitter(verdict.rounds_completed + 1)

    async def fetch_challenge(self, round_number: int) -> None:
        request = AskChallenge(self.group_id)
        event = self.challenge_events[round_number]
        started = time.monotonic()

        while not event.is_set() and time.monotonic() - started < 8.0:
            server = self.current_server()
            if server is not None:
                self.ez_send(server, request)
            try:
                await asyncio.wait_for(event.wait(), timeout=0.18)
            except asyncio.TimeoutError:
                continue

    async def gather_team_signatures(self, round_number: int, nonce: bytes) -> None:
        assert self.keys is not None
        request = PeerRound(self.group_id, round_number, nonce)
        started = time.monotonic()

        while len(self.signatures[round_number]) < TEAM_SIZE:
            deadline = self.deadlines.get(round_number, 0.0)
            if deadline and time.time() > deadline - 0.15:
                break
            if time.monotonic() - started > 8.5:
                break

            for slot, key in enumerate(self.keys):
                if slot == self.slot or slot in self.signatures[round_number]:
                    continue
                peer = self.lookup_peer(key)
                if peer is not None:
                    self.ez_send(peer, request)

            await asyncio.sleep(0.10)

    async def send_bundle_until_verdict(self, round_number: int) -> None:
        by_slot = self.signatures[round_number]
        payload = Bundle(
            self.group_id,
            round_number,
            by_slot[0],
            by_slot[1],
            by_slot[2],
        )
        event = self.verdict_events[round_number]
        started = time.monotonic()

        while not event.is_set() and time.monotonic() - started < 9.5:
            deadline = self.deadlines.get(round_number, 0.0)
            if deadline and time.time() > deadline + 0.8:
                break

            server = self.current_server()
            if server is not None:
                self.ez_send(server, payload)

            try:
                await asyncio.wait_for(event.wait(), timeout=0.18)
            except asyncio.TimeoutError:
                continue

    async def poke_next_submitter(self, round_number: int) -> None:
        assert self.keys is not None
        if round_number > FINAL_ROUND:
            return

        peer = self.lookup_peer(self.keys[round_number - 1])
        if peer is None:
            out(f"[round {round_number}] next submitter is not visible")
            return

        trigger = PeerRound(self.group_id, round_number, EMPTY_TRIGGER)
        out(f"[round {round_number}] waking member {round_number}")
        for _ in range(8):
            self.ez_send(peer, trigger)
            await asyncio.sleep(0.06)

    async def send_signature_back(self, peer: Peer, group_id: str, round_number: int, nonce: bytes) -> None:
        self.rounds_touched.add(round_number)
        signature = default_eccrypto.create_signature(self.my_peer.key, nonce)
        reply = PeerSignature(group_id, round_number, signature)

        for _ in range(4):
            self.ez_send(peer, reply)
            await asyncio.sleep(0.04)

    @lazy_wrapper(RegistrationAnswer)
    def handle_registration(self, peer: Peer, payload: RegistrationAnswer) -> None:
        if not self.is_server(peer):
            return

        if payload.success:
            self.group_id = payload.group_id
            out(f"[registration] {payload.message}: {self.group_id}")
        else:
            self.registration_failed = payload.message
            out(f"[registration] rejected: {payload.message}")
        self.registered.set()

    @lazy_wrapper(Challenge)
    def handle_challenge(self, peer: Peer, payload: Challenge) -> None:
        if not self.is_server(peer):
            return

        self.nonces[payload.round_number] = payload.nonce
        self.deadlines[payload.round_number] = payload.deadline

        event = self.challenge_events.get(payload.round_number)
        if event is not None:
            out(f"[round {payload.round_number}] challenge received")
            event.set()

    @lazy_wrapper(Verdict)
    def handle_verdict(self, peer: Peer, payload: Verdict) -> None:
        if not self.is_server(peer):
            return

        self.verdicts[payload.round_number] = payload
        event = self.verdict_events.get(payload.round_number)
        if event is not None:
            event.set()

        status = "ok" if payload.success else "no"
        out(f"[round {payload.round_number}] {status}: {payload.message}")
        if payload.success and payload.rounds_completed >= FINAL_ROUND:
            self.finished.set()
        if not payload.success and "budget exceeded" in payload.message:
            self.finished.set()

    @lazy_wrapper(PeerRound)
    def handle_peer_round(self, peer: Peer, payload: PeerRound) -> None:
        if self.keys is None or not self.is_team_peer(peer):
            return
        if self.group_id and payload.group_id != self.group_id:
            return
        if not self.group_id:
            self.group_id = payload.group_id

        if payload.round_number < 1 or payload.round_number > FINAL_ROUND:
            return

        submitter_key = self.keys[payload.round_number - 1]
        sender_key = peer.public_key.key_to_bin()

        if payload.nonce == EMPTY_TRIGGER:
            if self.keys[self.slot] == submitter_key:
                self.register_anonymous_task(
                    f"round-{payload.round_number}-submitter",
                    self.submitter_round(payload.round_number),
                )
            return

        if len(payload.nonce) != 32 or sender_key != submitter_key:
            return

        out(f"[round {payload.round_number}] signing for submitter")
        self.register_anonymous_task(
            f"round-{payload.round_number}-signer",
            self.send_signature_back(peer, payload.group_id, payload.round_number, payload.nonce),
        )

    @lazy_wrapper(PeerSignature)
    def handle_peer_signature(self, peer: Peer, payload: PeerSignature) -> None:
        if self.keys is None or not self.is_team_peer(peer):
            return
        if payload.group_id != self.group_id or len(payload.signature) != 64:
            return

        bucket = self.signatures.get(payload.round_number)
        if bucket is None:
            return

        signer_slot = list(self.keys).index(peer.public_key.key_to_bin())
        if signer_slot not in bucket:
            bucket[signer_slot] = payload.signature
            out(f"[round {payload.round_number}] signature from member {signer_slot + 1}")


def own_public_key(private_key_file: Path) -> bytes:
    with private_key_file.open("rb") as handle:
        return default_eccrypto.key_from_private_bin(handle.read()).pub().key_to_bin()


def hex_key(value: str, name: str) -> bytes | None:
    if not value:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal") from exc


def ordered_keys(args: argparse.Namespace, me: bytes) -> list[bytes]:
    member1 = hex_key(args.member1, "--member1")
    member2 = hex_key(args.member2, "--member2")
    member3 = hex_key(args.member3, "--member3")

    if args.role in ("coordinator", "member1"):
        member1 = member1 or me
        member2 = member2 or hex_key(args.peer2, "--peer2")
        member3 = member3 or hex_key(args.peer3, "--peer3")
    elif args.role == "member2":
        member2 = member2 or me
    elif args.role == "member3":
        member3 = member3 or me

    keys = [member1, member2, member3]
    if any(key is None for key in keys):
        raise ValueError("supply --member1, --member2 and --member3, or use role-based inference")

    result = [key for key in keys if key is not None]
    if len(set(result)) != TEAM_SIZE:
        raise ValueError("member keys must be unique")
    if me not in result:
        raise ValueError("your key is not in the canonical member order")
    return result


async def run(args: argparse.Namespace) -> int:
    if not args.key.exists():
        raise FileNotFoundError(f"{args.key} does not exist")

    public_key = own_public_key(args.key)
    keys = ordered_keys(args, public_key)
    should_start = args.start or args.role in ("coordinator", "member1")

    logging.disable(logging.CRITICAL)

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(args.port)
    builder.set_log_level("CRITICAL")
    builder.add_key("member-key", "curve25519", str(args.key))
    builder.add_overlay(
        "TeammateOverlay",
        "member-key",
        [WalkerDefinition(Strategy.RandomWalk, 1000, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"TeammateOverlay": TeammateOverlay})
    await ipv8.start()
    overlay: TeammateOverlay = ipv8.get_overlay(TeammateOverlay)
    overlay.install_group(keys, args.group_id)

    out(f"[system] port={args.port}")
    out(f"[system] public_key={public_key.hex()}")
    out(f"[system] member={keys.index(public_key) + 1}")

    try:
        if should_start:
            await overlay.register_or_reuse(args.discovery_timeout, args.retry_interval)
            await overlay.wait_for_full_team(args.discovery_timeout)
            await overlay.submitter_round(1)
        else:
            out("[system] waiting for teammate messages")

        try:
            await asyncio.wait_for(overlay.finished.wait(), timeout=args.runtime)
        except asyncio.TimeoutError:
            if overlay.rounds_touched:
                out("[system] timeout after participating; leaving client")
                return 0
            out("[system] timeout without participating")
            return 1

        return 0
    finally:
        await ipv8.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Alternative Lab 2 teammate client")
    parser.add_argument("--role", choices=["coordinator", "member1", "member2", "member3"], default="member2")
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument("--group-id", default="")

    parser.add_argument("--member1", default="")
    parser.add_argument("--member2", default="")
    parser.add_argument("--member3", default="")
    parser.add_argument("--peer2", default="", help="member1/coordinator shorthand for member2")
    parser.add_argument("--peer3", default="", help="member1/coordinator shorthand for member3")

    parser.add_argument("--start", action="store_true", help="register and start round 1 from this node")
    parser.add_argument("--discovery-timeout", type=float, default=120.0)
    parser.add_argument("--retry-interval", type=float, default=1.5)
    parser.add_argument("--runtime", type=float, default=180.0)
    return parser.parse_args()


def main() -> int:
    try:
        return asyncio.run(run(parse_args()))
    except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
        out(f"[error] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())