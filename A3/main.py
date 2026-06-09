from __future__ import annotations

import argparse
import asyncio
import hashlib
import inspect
import logging
import os
import signal
import struct
import time
from collections import OrderedDict, defaultdict
from contextlib import suppress
from dataclasses import dataclass
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


REGISTRATION_COMMUNITY_ID = bytes.fromhex("4c616233426c6f636b636861696e323032365057")
SERVER_PUBLIC_KEY = bytes.fromhex(
    "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350"
    "ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6"
)

GROUP_SIZE = 3
HASH_LEN = 32
GENESIS_PREV_HASH = b"\x00" * HASH_LEN
EMPTY_TXS_HASH = hashlib.sha256(b"").digest()


def log(message: str) -> None:
    print(message, flush=True)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def pack_i64(value: int) -> bytes:
    return struct.pack(">q", value)


def header_bytes(prev_hash: bytes, txs_hash: bytes, timestamp: int, difficulty: int, nonce: int) -> bytes:
    if len(prev_hash) != HASH_LEN or len(txs_hash) != HASH_LEN:
        raise ValueError("block hashes must be 32 bytes")
    if difficulty < 0 or difficulty > 2**32 - 1:
        raise ValueError("difficulty does not fit uint32")
    if timestamp < 0 or timestamp > 2**64 - 1:
        raise ValueError("timestamp does not fit uint64")
    if nonce < 0 or nonce > 2**64 - 1:
        raise ValueError("nonce does not fit uint64")
    return prev_hash + txs_hash + struct.pack(">QIQ", timestamp, difficulty, nonce)


def leading_zero_bits(digest: bytes) -> int:
    zeroes = 0
    for byte in digest:
        if byte == 0:
            zeroes += 8
            continue
        return zeroes + 8 - byte.bit_length()
    return len(digest) * 8


def satisfies_pow(digest: bytes, difficulty: int) -> bool:
    return 0 <= difficulty <= 256 and leading_zero_bits(digest) >= difficulty


def txs_commitment(tx_hashes: list[bytes] | tuple[bytes, ...]) -> bytes:
    return sha256(b"".join(tx_hashes))


def split_tx_hashes(raw: bytes) -> tuple[bytes, ...]:
    if len(raw) % HASH_LEN != 0:
        raise ValueError("tx_hashes length is not a multiple of 32")
    return tuple(raw[index : index + HASH_LEN] for index in range(0, len(raw), HASH_LEN))


@dataclass(frozen=True)
class Transaction:
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        return self.sender_key + self.data + pack_i64(self.timestamp)

    @property
    def tx_hash(self) -> bytes:
        return sha256(self.signed_bytes + self.signature)

    def verify(self) -> tuple[bool, str]:
        try:
            public_key = default_eccrypto.key_from_public_bin(self.sender_key)
        except Exception as exc:
            return False, f"invalid sender key: {exc}"
        try:
            if not default_eccrypto.is_valid_signature(public_key, self.signed_bytes, self.signature):
                return False, "invalid transaction signature"
        except Exception as exc:
            return False, f"signature verification failed: {exc}"
        return True, "accepted"


@dataclass(frozen=True)
class Block:
    height: int
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    tx_hashes: tuple[bytes, ...]

    @property
    def header(self) -> bytes:
        return header_bytes(self.prev_hash, self.txs_hash, self.timestamp, self.difficulty, self.nonce)

    @property
    def block_hash(self) -> bytes:
        return sha256(self.header)

    @property
    def tx_hashes_bytes(self) -> bytes:
        return b"".join(self.tx_hashes)

    def validate_self(self) -> tuple[bool, str]:
        if self.height < 0:
            return False, "negative height"
        if len(self.prev_hash) != HASH_LEN:
            return False, "prev_hash is not 32 bytes"
        if len(self.txs_hash) != HASH_LEN:
            return False, "txs_hash is not 32 bytes"
        if any(len(tx_hash) != HASH_LEN for tx_hash in self.tx_hashes):
            return False, "transaction hash is not 32 bytes"
        if txs_commitment(self.tx_hashes) != self.txs_hash:
            return False, "body commitment mismatch"
        try:
            block_hash = self.block_hash
        except ValueError as exc:
            return False, f"invalid header field: {exc}"
        if not satisfies_pow(block_hash, self.difficulty):
            return False, "invalid proof of work"
        return True, "valid"


def genesis_block() -> Block:
    return Block(
        height=0,
        prev_hash=GENESIS_PREV_HASH,
        txs_hash=EMPTY_TXS_HASH,
        timestamp=0,
        difficulty=0,
        nonce=0,
        tx_hashes=(),
    )


async def mine_block(
    height: int,
    prev_hash: bytes,
    tx_hashes: tuple[bytes, ...],
    difficulty: int,
    expected_tip: bytes,
    current_tip,
) -> Block | None:
    txs_hash = txs_commitment(tx_hashes)
    timestamp = int(time.time())
    nonce = 0

    while nonce <= 2**63 - 1:
        if current_tip() != expected_tip:
            return None

        digest = sha256(header_bytes(prev_hash, txs_hash, timestamp, difficulty, nonce))
        if satisfies_pow(digest, difficulty):
            return Block(height, prev_hash, txs_hash, timestamp, difficulty, nonce, tx_hashes)

        nonce += 1
        if nonce % 5000 == 0:
            await asyncio.sleep(0)

    raise RuntimeError("nonce range exhausted")


class RegisterBlockchain(VariablePayloadWID):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenH"]
    names = ["group_id", "community_id"]


class RegisterResponse(VariablePayloadWID):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]


class SubmitTransaction(VariablePayloadWID):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "q", "varlenH"]
    names = ["sender_key", "data", "timestamp", "signature"]


class SubmitTransactionResponse(VariablePayloadWID):
    msg_id = 2
    format_list = ["?", "varlenH", "varlenHutf8"]
    names = ["success", "tx_hash", "message"]


class GetChainHeight(VariablePayloadWID):
    msg_id = 3
    format_list = ["q"]
    names = ["request_id"]


class ChainHeightResponse(VariablePayloadWID):
    msg_id = 4
    format_list = ["q", "q", "varlenH"]
    names = ["request_id", "height", "tip_hash"]


class GetBlock(VariablePayloadWID):
    msg_id = 5
    format_list = ["q"]
    names = ["height"]


class BlockResponse(VariablePayloadWID):
    msg_id = 6
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
    names = [
        "height",
        "prev_hash",
        "txs_hash",
        "timestamp",
        "difficulty",
        "nonce",
        "block_hash",
        "tx_hashes",
    ]


class PeerBlock(VariablePayloadWID):
    msg_id = 10
    format_list = ["q", "varlenH", "varlenH", "q", "q", "q", "varlenH", "varlenH"]
    names = BlockResponse.names


class RegistrationCommunity(Community):
    community_id = REGISTRATION_COMMUNITY_ID

    def __init__(self, settings) -> None:
        super().__init__(settings)
        self.add_message_handler(RegisterResponse, self.on_register_response)
        self.group_id = ""
        self.blockchain_community_id = b""
        self.registered = asyncio.Event()
        self.last_response: RegisterResponse | None = None

    def configure(self, group_id: str, blockchain_community_id: bytes) -> None:
        self.group_id = group_id
        self.blockchain_community_id = blockchain_community_id

    def is_server(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY

    def server_peer(self) -> Peer | None:
        return next((peer for peer in self.get_peers() if self.is_server(peer)), None)

    async def registration_loop(self, retry_interval: float) -> None:
        payload = RegisterBlockchain(self.group_id, self.blockchain_community_id)
        attempts = 0

        while not self.registered.is_set():
            server = self.server_peer()
            if server is None:
                log(f"[registration] waiting for verified server; known peers={len(self.get_peers())}")
                await asyncio.sleep(retry_interval)
                continue

            attempts += 1
            log(f"[registration] sending Lab 3 registration attempt {attempts}")
            self.ez_send(server, payload)

            try:
                await asyncio.wait_for(self.registered.wait(), timeout=retry_interval)
            except asyncio.TimeoutError:
                pass

    @lazy_wrapper(RegisterResponse)
    def on_register_response(self, peer: Peer, payload: RegisterResponse) -> None:
        if not self.is_server(peer):
            return

        self.last_response = payload
        status = "ok" if payload.success else "rejected"
        log(f"[registration] {status}: {payload.message}")
        if payload.success:
            self.registered.set()


class BlockchainCommunity(Community):
    community_id = b"\x00" * 20

    def __init__(self, settings) -> None:
        super().__init__(settings)
        self.add_message_handler(SubmitTransaction, self.on_submit_transaction)
        self.add_message_handler(SubmitTransactionResponse, self.on_submit_transaction_response)
        self.add_message_handler(GetChainHeight, self.on_get_chain_height)
        self.add_message_handler(ChainHeightResponse, self.on_chain_height_response)
        self.add_message_handler(GetBlock, self.on_get_block)
        self.add_message_handler(BlockResponse, self.on_block_response)
        self.add_message_handler(PeerBlock, self.on_peer_block)

        self.member_keys: list[bytes] = []
        self.my_key: bytes = b""
        self.my_index = -1
        self.difficulty = 8
        self.block_interval = 1.0
        self.max_txs_per_block = 100
        self.debug_peers = False

        genesis = genesis_block()
        self.blocks: dict[bytes, Block] = {genesis.block_hash: genesis}
        self.canonical: list[Block] = [genesis]
        self.orphans: dict[bytes, list[Block]] = defaultdict(list)
        self.seen_orphans: set[bytes] = set()
        self.tx_objects: dict[bytes, Transaction] = {}
        self.mempool: OrderedDict[bytes, Transaction] = OrderedDict()
        self.confirmed_txs: set[bytes] = set()
        self.request_counter = int(time.time())
        self.last_tip_change = time.monotonic()

    def configure(
        self,
        member_keys: list[bytes],
        difficulty: int,
        block_interval: float,
        max_txs_per_block: int,
        debug_peers: bool,
    ) -> None:
        if len(member_keys) != GROUP_SIZE:
            raise ValueError("exactly 3 member public keys are required")
        if len(set(member_keys)) != GROUP_SIZE:
            raise ValueError("member public keys must be unique")
        if difficulty < 0 or difficulty > 256:
            raise ValueError("difficulty must be between 0 and 256 leading zero bits")
        if block_interval < 0:
            raise ValueError("block interval must be non-negative")
        if max_txs_per_block < 1:
            raise ValueError("max transactions per block must be at least 1")

        self.my_key = self.my_peer.public_key.key_to_bin()
        if self.my_key not in member_keys:
            raise ValueError("the configured private key is not in the member list")

        self.member_keys = member_keys
        self.my_index = member_keys.index(self.my_key)
        self.difficulty = difficulty
        self.block_interval = block_interval
        self.max_txs_per_block = max_txs_per_block
        self.debug_peers = debug_peers

    @property
    def tip(self) -> Block:
        return self.canonical[-1]

    def is_server(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY

    def is_member(self, peer: Peer) -> bool:
        return peer.public_key.key_to_bin() in self.member_keys

    def teammate_peers(self) -> list[Peer]:
        return [
            peer
            for peer in self.get_peers()
            if self.is_member(peer) and peer.public_key.key_to_bin() != self.my_key
        ]

    def peer_label(self, peer: Peer) -> str:
        key = peer.public_key.key_to_bin()
        if key == SERVER_PUBLIC_KEY:
            return "server"
        if key in self.member_keys:
            return f"member{self.member_keys.index(key) + 1}"
        return "unknown"

    def to_block_response(self, block: Block) -> BlockResponse:
        return BlockResponse(
            block.height,
            block.prev_hash,
            block.txs_hash,
            block.timestamp,
            block.difficulty,
            block.nonce,
            block.block_hash,
            block.tx_hashes_bytes,
        )

    def to_peer_block(self, block: Block) -> PeerBlock:
        return PeerBlock(
            block.height,
            block.prev_hash,
            block.txs_hash,
            block.timestamp,
            block.difficulty,
            block.nonce,
            block.block_hash,
            block.tx_hashes_bytes,
        )

    def payload_to_block(self, payload: BlockResponse | PeerBlock) -> tuple[Block | None, str]:
        try:
            tx_hashes = split_tx_hashes(payload.tx_hashes)
            block = Block(
                payload.height,
                payload.prev_hash,
                payload.txs_hash,
                payload.timestamp,
                payload.difficulty,
                payload.nonce,
                tx_hashes,
            )
        except Exception as exc:
            return None, f"malformed block payload: {exc}"

        ok, message = block.validate_self()
        if not ok:
            return None, message
        if block.block_hash != payload.block_hash:
            return None, "block_hash does not match header"
        return block, "valid"

    def broadcast_transaction(self, tx: Transaction, exclude: bytes | None = None) -> None:
        payload = SubmitTransaction(tx.sender_key, tx.data, tx.timestamp, tx.signature)
        for peer in self.teammate_peers():
            if exclude is not None and peer.public_key.key_to_bin() == exclude:
                continue
            self.ez_send(peer, payload)

    def broadcast_block(self, block: Block, exclude: bytes | None = None) -> None:
        payload = self.to_peer_block(block)
        for peer in self.teammate_peers():
            if exclude is not None and peer.public_key.key_to_bin() == exclude:
                continue
            self.ez_send(peer, payload)

    def add_transaction(self, tx: Transaction) -> tuple[bool, bytes, str]:
        tx_hash = tx.tx_hash
        ok, message = tx.verify()
        if not ok:
            return False, tx_hash, message

        self.tx_objects[tx_hash] = tx
        if tx_hash in self.confirmed_txs:
            return True, tx_hash, "already confirmed"
        if tx_hash in self.mempool:
            return True, tx_hash, "already in mempool"

        self.mempool[tx_hash] = tx
        log(f"[tx] accepted {tx_hash.hex()} mempool={len(self.mempool)}")
        return True, tx_hash, "accepted"

    def block_parent_known(self, block: Block) -> bool:
        parent = self.blocks.get(block.prev_hash)
        return parent is not None and parent.height == block.height - 1

    def add_block(self, block: Block, source: str) -> bool:
        ok, message = block.validate_self()
        if not ok:
            log(f"[block] rejected height={block.height} from {source}: {message}")
            return False

        block_hash = block.block_hash
        if block_hash in self.blocks:
            return False

        if block.height == 0:
            return block_hash == self.canonical[0].block_hash

        if not self.block_parent_known(block):
            if block_hash not in self.seen_orphans:
                self.orphans[block.prev_hash].append(block)
                self.seen_orphans.add(block_hash)
                log(f"[sync] stored orphan height={block.height}; requesting missing parents")
                self.request_missing_blocks(block.height)
            return False

        self.blocks[block_hash] = block
        if self.is_better_tip(block):
            self.switch_to_tip(block)

        for child in list(self.orphans.pop(block_hash, [])):
            self.seen_orphans.discard(child.block_hash)
            self.add_block(child, f"orphan/{source}")

        return True

    def is_better_tip(self, candidate: Block) -> bool:
        tip = self.tip
        if candidate.height > tip.height:
            return True
        return candidate.height == tip.height and candidate.block_hash < tip.block_hash

    def switch_to_tip(self, new_tip: Block) -> None:
        chain: list[Block] = []
        cursor = new_tip
        while True:
            chain.append(cursor)
            if cursor.height == 0:
                break
            parent = self.blocks.get(cursor.prev_hash)
            if parent is None:
                return
            cursor = parent

        chain.reverse()
        if chain[0].block_hash != self.canonical[0].block_hash:
            return
        if any(block.height != index for index, block in enumerate(chain)):
            return

        old_tip = self.tip
        self.canonical = chain
        self.rebuild_confirmed_and_mempool()
        self.last_tip_change = time.monotonic()
        if new_tip.block_hash != old_tip.block_hash:
            log(
                f"[chain] tip height={new_tip.height} hash={new_tip.block_hash.hex()} "
                f"txs={len(new_tip.tx_hashes)}"
            )

    def rebuild_confirmed_and_mempool(self) -> None:
        confirmed: set[bytes] = set()
        for block in self.canonical:
            confirmed.update(block.tx_hashes)
        self.confirmed_txs = confirmed

        refreshed: OrderedDict[bytes, Transaction] = OrderedDict()
        for tx_hash, tx in self.tx_objects.items():
            if tx_hash not in confirmed:
                refreshed[tx_hash] = tx
        self.mempool = refreshed

    def request_missing_blocks(self, up_to_height: int | None = None) -> None:
        max_height = up_to_height if up_to_height is not None else self.tip.height + 12
        start = max(1, self.tip.height + 1)
        for peer in self.teammate_peers():
            for height in range(start, max_height + 1):
                self.ez_send(peer, GetBlock(height))

    async def mining_loop(self) -> None:
        log(
            f"[mining] member{self.my_index + 1}; difficulty={self.difficulty}; "
            f"interval={self.block_interval:.2f}s"
        )
        while True:
            next_height = self.tip.height + 1
            miner_index = (next_height - 1) % GROUP_SIZE
            if miner_index != self.my_index:
                await asyncio.sleep(0.20)
                continue

            since_tip = time.monotonic() - self.last_tip_change
            if since_tip < self.block_interval:
                await asyncio.sleep(min(0.20, self.block_interval - since_tip))
                continue

            tx_hashes = tuple(list(self.mempool.keys())[: self.max_txs_per_block])
            expected_tip = self.tip.block_hash
            block = await mine_block(
                next_height,
                expected_tip,
                tx_hashes,
                self.difficulty,
                expected_tip,
                lambda: self.tip.block_hash,
            )
            if block is None:
                continue

            if self.add_block(block, "local"):
                self.broadcast_block(block)

            await asyncio.sleep(0.05)

    async def sync_loop(self) -> None:
        last_debug = 0.0
        while True:
            self.request_counter += 1
            request = GetChainHeight(self.request_counter)
            for peer in self.teammate_peers():
                self.ez_send(peer, request)
            for tx in list(self.mempool.values()):
                self.broadcast_transaction(tx)
            if self.tip.height > 0:
                self.broadcast_block(self.tip)

            if self.debug_peers and time.monotonic() - last_debug > 5.0:
                last_debug = time.monotonic()
                labels = [f"{self.peer_label(peer)}@{peer.address}" for peer in self.get_peers()]
                log(
                    f"[debug] tip={self.tip.height}:{self.tip.block_hash.hex()[:16]} "
                    f"mempool={len(self.mempool)} peers={labels}"
                )

            await asyncio.sleep(2.0)

    @lazy_wrapper(SubmitTransaction)
    def on_submit_transaction(self, peer: Peer, payload: SubmitTransaction) -> None:
        if not (self.is_server(peer) or self.is_member(peer)):
            return

        tx = Transaction(payload.sender_key, payload.data, payload.timestamp, payload.signature)
        accepted, tx_hash, message = self.add_transaction(tx)
        self.ez_send(peer, SubmitTransactionResponse(accepted, tx_hash, message))
        if accepted:
            self.broadcast_transaction(tx, exclude=peer.public_key.key_to_bin())

    @lazy_wrapper(SubmitTransactionResponse)
    def on_submit_transaction_response(self, peer: Peer, payload: SubmitTransactionResponse) -> None:
        if self.is_member(peer) and not payload.success:
            log(f"[tx] teammate rejected {payload.tx_hash.hex()}: {payload.message}")

    @lazy_wrapper(GetChainHeight)
    def on_get_chain_height(self, peer: Peer, payload: GetChainHeight) -> None:
        if not (self.is_server(peer) or self.is_member(peer)):
            return
        self.ez_send(peer, ChainHeightResponse(payload.request_id, self.tip.height, self.tip.block_hash))

    @lazy_wrapper(ChainHeightResponse)
    def on_chain_height_response(self, peer: Peer, payload: ChainHeightResponse) -> None:
        if not self.is_member(peer):
            return
        if payload.height > self.tip.height:
            end = min(payload.height, self.tip.height + 24)
            for height in range(self.tip.height + 1, end + 1):
                self.ez_send(peer, GetBlock(height))
        elif payload.height == self.tip.height and payload.tip_hash != self.tip.block_hash:
            self.ez_send(peer, GetBlock(payload.height))

    @lazy_wrapper(GetBlock)
    def on_get_block(self, peer: Peer, payload: GetBlock) -> None:
        if not (self.is_server(peer) or self.is_member(peer)):
            return
        if payload.height < 0 or payload.height >= len(self.canonical):
            return
        self.ez_send(peer, self.to_block_response(self.canonical[payload.height]))

    @lazy_wrapper(BlockResponse)
    def on_block_response(self, peer: Peer, payload: BlockResponse) -> None:
        if not self.is_member(peer):
            return
        block, message = self.payload_to_block(payload)
        if block is None:
            log(f"[sync] invalid block response from {self.peer_label(peer)}: {message}")
            return
        if self.add_block(block, f"response/{self.peer_label(peer)}"):
            self.broadcast_block(block, exclude=peer.public_key.key_to_bin())

    @lazy_wrapper(PeerBlock)
    def on_peer_block(self, peer: Peer, payload: PeerBlock) -> None:
        if not self.is_member(peer):
            return
        block, message = self.payload_to_block(payload)
        if block is None:
            log(f"[sync] invalid block from {self.peer_label(peer)}: {message}")
            return
        if self.add_block(block, self.peer_label(peer)):
            self.broadcast_block(block, exclude=peer.public_key.key_to_bin())


def read_public_key(private_key_file: Path) -> bytes:
    if not private_key_file.exists():
        raise FileNotFoundError(f"{private_key_file} does not exist")
    with private_key_file.open("rb") as handle:
        return default_eccrypto.key_from_private_bin(handle.read()).pub().key_to_bin()


def parse_hex(value: str, name: str) -> bytes | None:
    if not value:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal") from exc


def parse_community_id(value: str, group_id: str, member_keys: list[bytes]) -> bytes:
    explicit = parse_hex(value, "--community-id")
    if explicit is not None:
        if len(explicit) != 20:
            raise ValueError("--community-id must be exactly 20 bytes / 40 hex characters")
        return explicit
    if not group_id:
        raise ValueError("provide --community-id or --group-id so a deterministic community ID can be derived")

    seed = b"Lab3Blockchain2026PW:" + group_id.encode("utf-8") + b":" + b"".join(member_keys)
    return sha256(seed)[:20]


def default_key_file() -> Path:
    lab1_key = Path("A1/marco/private_key.pem")
    return lab1_key if lab1_key.exists() else Path("private_key.pem")


async def stop_ipv8(ipv8: IPv8) -> None:
    """Avoid IPv8.stop() overlay-lock re-entry in the version used by this lab VM."""
    if ipv8.state_machine_task:
        ipv8.state_machine_task.cancel()
        with suppress(asyncio.CancelledError):
            await ipv8.state_machine_task

    for overlay in list(ipv8.overlays):
        with suppress(Exception):
            await overlay.unload()

    close_result = ipv8.endpoint.close()
    if inspect.isawaitable(close_result):
        await close_result


def ordered_member_keys(args: argparse.Namespace, own_key: bytes) -> list[bytes]:
    member1 = parse_hex(args.member1, "--member1")
    member2 = parse_hex(args.member2, "--member2")
    member3 = parse_hex(args.member3, "--member3")

    if args.role in ("coordinator", "member1"):
        member1 = member1 or own_key
        member2 = member2 or parse_hex(args.peer2, "--peer2")
        member3 = member3 or parse_hex(args.peer3, "--peer3")
    elif args.role == "member2":
        member2 = member2 or own_key
    elif args.role == "member3":
        member3 = member3 or own_key

    keys = [member1, member2, member3]
    if any(key is None for key in keys):
        raise ValueError(
            "provide --member1, --member2, and --member3 "
            "(member1/coordinator may use --peer2 and --peer3)"
        )

    result = [key for key in keys if key is not None]
    if len(set(result)) != GROUP_SIZE:
        raise ValueError("member public keys must be distinct")
    if own_key not in result:
        raise ValueError("your private key's public key is not in the member list")
    return result


async def run(args: argparse.Namespace) -> int:
    own_key = read_public_key(args.key_file)
    member_keys = ordered_member_keys(args, own_key)
    community_id = parse_community_id(args.community_id, args.group_id, member_keys)

    if not args.no_register and not args.group_id:
        raise ValueError("--group-id is required unless --no-register is used")

    logging.disable(logging.CRITICAL)
    BlockchainCommunity.community_id = community_id

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(args.port)
    builder.set_log_level("CRITICAL")
    builder.add_key("lab3_key", args.key_type, str(args.key_file))
    builder.add_overlay(
        "RegistrationCommunity",
        "lab3_key",
        [WalkerDefinition(Strategy.RandomWalk, 1000, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )
    builder.add_overlay(
        "BlockchainCommunity",
        "lab3_key",
        [WalkerDefinition(Strategy.RandomWalk, 1000, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )

    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={
            "RegistrationCommunity": RegistrationCommunity,
            "BlockchainCommunity": BlockchainCommunity,
        },
    )
    await ipv8.start()
    loop = asyncio.get_running_loop()
    with suppress(NotImplementedError, RuntimeError):
        loop.add_signal_handler(signal.SIGINT, lambda: os._exit(0))
        loop.add_signal_handler(signal.SIGTERM, lambda: os._exit(0))

    registration: RegistrationCommunity = ipv8.get_overlay(RegistrationCommunity)
    blockchain: BlockchainCommunity = ipv8.get_overlay(BlockchainCommunity)
    registration.configure(args.group_id, community_id)
    blockchain.configure(
        member_keys,
        difficulty=args.difficulty,
        block_interval=args.block_interval,
        max_txs_per_block=args.max_txs_per_block,
        debug_peers=args.debug_peers,
    )

    log(f"[system] UDP port: {args.port}")
    log(f"[system] public key: {own_key.hex()}")
    log(f"[system] member index: {member_keys.index(own_key) + 1}")
    log(f"[system] blockchain community id: {community_id.hex()}")
    log(f"[system] genesis hash: {blockchain.tip.block_hash.hex()}")

    tasks: list[asyncio.Task] = [
        asyncio.create_task(blockchain.mining_loop(), name="lab3-mining"),
        asyncio.create_task(blockchain.sync_loop(), name="lab3-sync"),
    ]
    if not args.no_register:
        tasks.append(asyncio.create_task(registration.registration_loop(args.register_retry), name="lab3-register"))

    try:
        if args.runtime > 0:
            await asyncio.sleep(args.runtime)
            log("[system] runtime reached; exiting")
            os._exit(0)
        else:
            await asyncio.Event().wait()
        return 0
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await stop_ipv8(ipv8)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lab 3 Proof-of-Work blockchain IPv8 node")
    parser.add_argument(
        "--role",
        choices=["coordinator", "member", "member1", "member2", "member3"],
        default="member",
        help="used only to infer your own key position when some member keys are omitted",
    )
    parser.add_argument("--key-file", "--key", type=Path, default=default_key_file())
    parser.add_argument(
        "--key-type",
        choices=["curve25519", "very-low", "low", "medium", "high"],
        default="curve25519",
        help="used only if the key file does not already exist",
    )
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--group-id", default="", help="Lab 2 group ID used for server registration")
    parser.add_argument(
        "--community-id",
        default="",
        help="20-byte blockchain community id as 40 hex chars; omitted means derive from group/member keys",
    )
    parser.add_argument("--no-register", action="store_true", help="run the blockchain without registering it")

    parser.add_argument("--member1", default="", help="canonical member 1 public key hex")
    parser.add_argument("--member2", default="", help="canonical member 2 public key hex")
    parser.add_argument("--member3", default="", help="canonical member 3 public key hex")
    parser.add_argument("--peer2", default="", help="member1/coordinator shorthand for member 2 public key hex")
    parser.add_argument("--peer3", default="", help="member1/coordinator shorthand for member 3 public key hex")

    parser.add_argument("--difficulty", type=int, default=8, help="declared leading-zero-bit PoW difficulty")
    parser.add_argument("--block-interval", type=float, default=1.0, help="seconds between accepted tips and mining")
    parser.add_argument("--max-txs-per-block", type=int, default=100)
    parser.add_argument("--register-retry", type=float, default=3.0)
    parser.add_argument("--runtime", type=float, default=0.0, help="seconds to run; 0 means run until interrupted")
    parser.add_argument("--debug-peers", action="store_true")
    return parser.parse_args()


def main() -> int:
    try:
        return asyncio.run(run(parse_args()))
    except KeyboardInterrupt:
        log("[system] stopped")
        return 0
    except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
        log(f"[error] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
