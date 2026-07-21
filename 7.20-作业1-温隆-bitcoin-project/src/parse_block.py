#!/usr/bin/env python3
"""
Independently parse and verify a complete serialized Bitcoin block.

Default inputs:
  data/raw_block.hex
  data/raw_transaction.hex
  data/metadata.json

This program does not call Bitcoin Core. It:
  - parses the 80-byte block header;
  - parses every transaction using src/parse_transaction.py;
  - identifies the Coinbase transaction and BIP34 block height;
  - recomputes the transaction Merkle root;
  - recomputes the block hash;
  - expands nBits into the full proof-of-work target;
  - verifies block_hash <= target;
  - verifies the SegWit witness commitment when present;
  - confirms that the experiment transaction is present at the expected index.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, getcontext
from pathlib import Path
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from parse_transaction import (  # noqa: E402
    ByteReader,
    ParseError as TransactionParseError,
    display_hash,
    format_bits,
    hash256,
    parse_transaction,
    read_script_pushes,
)

DEFAULT_BLOCK_PATH = PROJECT_ROOT / "data" / "raw_block.hex"
DEFAULT_TX_PATH = PROJECT_ROOT / "data" / "raw_transaction.hex"
DEFAULT_METADATA_PATH = PROJECT_ROOT / "data" / "metadata.json"

# Bitcoin's historical difficulty-1 target.
DIFFICULTY_ONE_TARGET = int(
    "00000000ffff0000000000000000000000000000000000000000000000000000",
    16,
)


class BlockParseError(ValueError):
    """Raised when a block is malformed or a verification check fails."""


@dataclass(frozen=True)
class HeaderField:
    name: str
    offset: int
    length: int
    raw_hex: str
    value: str
    meaning: str


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BlockParseError(message)


def read_hex(path: Path) -> bytes:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise BlockParseError(f"Missing file: {path}") from exc

    if not text:
        raise BlockParseError(f"Hex file is empty: {path}")

    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise BlockParseError(f"Invalid hexadecimal data in {path}: {exc}") from exc


def load_metadata(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BlockParseError(f"Missing metadata file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BlockParseError(f"Invalid metadata JSON: {exc}") from exc


def compact_target(bits: int) -> dict[str, Any]:
    """
    Expand Bitcoin's compact nBits representation.

    nBits consists of:
      exponent = most-significant byte
      coefficient = lower 23 bits
      sign flag = bit 23
    """
    exponent = bits >> 24
    coefficient = bits & 0x007FFFFF
    negative = bool(bits & 0x00800000)

    if exponent <= 3:
        target = coefficient >> (8 * (3 - exponent))
    else:
        target = coefficient << (8 * (exponent - 3))

    overflow = (
        coefficient != 0
        and (
            exponent > 34
            or (coefficient > 0xFF and exponent > 33)
            or (coefficient > 0xFFFF and exponent > 32)
        )
    )

    return {
        "bits": bits,
        "exponent": exponent,
        "coefficient": coefficient,
        "negative": negative,
        "overflow": overflow,
        "target": target,
        "target_hex": f"{target:064x}",
    }


def merkle_root_from_internal(nodes: list[bytes]) -> tuple[bytes, list[int]]:
    """
    Compute a Bitcoin Merkle root from internal-order 32-byte hashes.

    At each odd-width level, the last hash is duplicated.
    """
    if not nodes:
        raise BlockParseError("Cannot build a Merkle tree with zero leaves.")

    for node in nodes:
        if len(node) != 32:
            raise BlockParseError("Merkle leaf is not 32 bytes.")

    current = list(nodes)
    widths = [len(current)]

    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])

        current = [
            hash256(current[index] + current[index + 1])
            for index in range(0, len(current), 2)
        ]
        widths.append(len(current))

    return current[0], widths


def merkle_root_from_display_hashes(hashes: Iterable[str]) -> tuple[bytes, list[int]]:
    internal = [bytes.fromhex(value)[::-1] for value in hashes]
    return merkle_root_from_internal(internal)


def decode_script_number(raw: bytes) -> int:
    """Decode Bitcoin Script's little-endian signed-magnitude integer."""
    if not raw:
        return 0

    data = bytearray(raw)
    negative = bool(data[-1] & 0x80)
    data[-1] &= 0x7F
    value = int.from_bytes(data, "little", signed=False)
    return -value if negative else value


def first_script_push(script: bytes) -> bytes | None:
    """Read the first push from a script, sufficient for BIP34 height."""
    if not script:
        return None

    opcode = script[0]
    offset = 1

    if 1 <= opcode <= 75:
        length = opcode
    elif opcode == 0x4C:
        if len(script) < 2:
            return None
        length = script[1]
        offset = 2
    elif opcode == 0x4D:
        if len(script) < 3:
            return None
        length = int.from_bytes(script[1:3], "little")
        offset = 3
    else:
        return None

    end = offset + length
    if end > len(script):
        return None
    return script[offset:end]


def parse_coinbase_height(transaction: dict[str, Any]) -> int | None:
    if not transaction["inputs"]:
        return None

    script = bytes.fromhex(transaction["inputs"][0]["scriptSig_hex"])
    first_push = first_script_push(script)
    if first_push is None:
        return None
    return decode_script_number(first_push)


def block_subsidy_sat(height: int) -> int:
    """Return the scheduled Bitcoin block subsidy at a given height."""
    if height < 0:
        raise BlockParseError("Block height cannot be negative.")

    halvings = height // 210_000
    if halvings >= 64:
        return 0
    return (50 * 100_000_000) >> halvings


def printable_ascii(data: bytes) -> str | None:
    """Return ASCII text only when every byte is printable."""
    if data and all(0x20 <= byte <= 0x7E for byte in data):
        return data.decode("ascii")
    return None


def analyze_coinbase_script_sig(
    transaction: dict[str, Any],
) -> list[dict[str, Any]]:
    """Parse Coinbase scriptSig push items without over-interpreting miner data."""
    if not transaction["inputs"]:
        return []

    script = bytes.fromhex(transaction["inputs"][0]["scriptSig_hex"])
    try:
        pushes = read_script_pushes(script)
    except TransactionParseError as exc:
        raise BlockParseError(f"Invalid Coinbase scriptSig: {exc}") from exc

    analysis: list[dict[str, Any]] = []
    for index, push in enumerate(pushes):
        data = push["data"]
        item: dict[str, Any] = {
            "index": index,
            "opcode_name": push["opcode_name"],
            "length": push["length"],
            "data_hex": data.hex(),
            "ascii": printable_ascii(data),
            "role": "miner-defined data",
        }

        if index == 0:
            item["role"] = "BIP34 block height"
            item["script_number"] = decode_script_number(data)
        elif item["ascii"] is not None:
            item["role"] = "printable miner tag/message"
        else:
            item["role"] = "miner-defined binary data / extraNonce candidate"

        analysis.append(item)

    return analysis


def is_coinbase(transaction: dict[str, Any]) -> bool:
    if len(transaction["inputs"]) != 1:
        return False

    item = transaction["inputs"][0]
    return (
        item["previous_txid"] == "00" * 32
        and item["previous_vout"] == 0xFFFFFFFF
    )


def find_witness_commitment(
    coinbase: dict[str, Any],
) -> tuple[int, bytes] | None:
    """
    Return the highest-index output beginning with:
      OP_RETURN 0x24 aa21a9ed <32-byte commitment>
    """
    found: tuple[int, bytes] | None = None

    for output in coinbase["outputs"]:
        script = bytes.fromhex(output["scriptPubKey_hex"])
        if len(script) >= 38 and script[:6] == bytes.fromhex("6a24aa21a9ed"):
            found = (output["index"], script[6:38])

    return found


def verify_witness_commitment(
    transactions: list[dict[str, Any]],
) -> dict[str, Any]:
    coinbase = transactions[0]
    commitment = find_witness_commitment(coinbase)

    if commitment is None:
        return {
            "present": False,
            "verified": None,
            "reason": "No witness commitment output is present.",
        }

    output_index, committed_hash = commitment

    witness_items = coinbase["inputs"][0].get("witness", [])
    if not witness_items:
        return {
            "present": True,
            "verified": False,
            "output_index": output_index,
            "committed_hash": committed_hash.hex(),
            "reason": "Coinbase witness reserved value is missing.",
        }

    reserved_value = bytes.fromhex(witness_items[0])
    if len(reserved_value) != 32:
        return {
            "present": True,
            "verified": False,
            "output_index": output_index,
            "committed_hash": committed_hash.hex(),
            "reserved_value": reserved_value.hex(),
            "reason": "Coinbase witness reserved value is not 32 bytes.",
        }

    # Consensus witness Merkle tree uses a zero hash for the Coinbase leaf.
    leaves = [b"\x00" * 32]
    leaves.extend(
        bytes.fromhex(transaction["wtxid"])[::-1]
        for transaction in transactions[1:]
    )

    witness_root, widths = merkle_root_from_internal(leaves)
    computed_commitment = hash256(witness_root + reserved_value)

    return {
        "present": True,
        "verified": computed_commitment == committed_hash,
        "output_index": output_index,
        "committed_hash": committed_hash.hex(),
        "computed_hash": computed_commitment.hex(),
        "witness_merkle_root_internal": witness_root.hex(),
        "witness_merkle_root_display": witness_root[::-1].hex(),
        "reserved_value": reserved_value.hex(),
        "level_widths": widths,
    }


def format_timestamp(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def print_header_table(fields: list[HeaderField]) -> None:
    print("=" * 124)
    print("BLOCK HEADER AND TRANSACTION-COUNT FIELD TABLE")
    print("=" * 124)
    print(
        f"{'Offset':>8}  {'Len':>5}  {'Field':<24}  "
        f"{'Raw bytes':<65}  Parsed value"
    )
    print("-" * 124)

    for field in fields:
        raw = field.raw_hex
        if len(raw) > 63:
            raw = raw[:30] + "..." + raw[-30:]
        print(
            f"{field.offset:8d}  {field.length:5d}  {field.name:<24}  "
            f"{raw:<65}  {field.value}"
        )

    print("-" * 124)


def parse_block(
    raw: bytes,
    *,
    network: str = "testnet4",
) -> dict[str, Any]:
    require(len(raw) >= 81, "Raw block is too short.")

    header = raw[:80]

    version_raw = header[0:4]
    previous_raw = header[4:36]
    merkle_raw = header[36:68]
    timestamp_raw = header[68:72]
    bits_raw = header[72:76]
    nonce_raw = header[76:80]

    version = int.from_bytes(version_raw, "little")
    previous_block_hash = previous_raw[::-1].hex()
    header_merkle_root = merkle_raw[::-1].hex()
    timestamp = int.from_bytes(timestamp_raw, "little")
    bits = int.from_bytes(bits_raw, "little")
    nonce = int.from_bytes(nonce_raw, "little")

    block_hash_internal = hash256(header)
    block_hash = display_hash(block_hash_internal)
    block_hash_integer = int.from_bytes(block_hash_internal, "little")

    target_info = compact_target(bits)
    require(not target_info["negative"], "nBits encodes a negative target.")
    require(not target_info["overflow"], "nBits target overflows 256 bits.")
    require(target_info["target"] > 0, "nBits target is zero.")

    pow_valid = block_hash_integer <= target_info["target"]

    reader = ByteReader(raw, 80)
    count_offset, count_raw, transaction_count = reader.read_compact_size()

    transactions: list[dict[str, Any]] = []
    transaction_offsets: list[int] = []

    for index in range(transaction_count):
        transaction_offsets.append(reader.offset)
        try:
            transaction, end_offset = parse_transaction(
                raw,
                reader.offset,
                network=network,
            )
        except TransactionParseError as exc:
            raise BlockParseError(
                f"Transaction {index} failed at block offset "
                f"{reader.offset}: {exc}"
            ) from exc

        transaction["block_index"] = index
        transactions.append(transaction)
        reader.offset = end_offset

    require(
        reader.offset == len(raw),
        f"Block parsing stopped at byte {reader.offset}, "
        f"but file contains {len(raw)} bytes.",
    )

    require(transactions, "Block contains no transactions.")
    require(is_coinbase(transactions[0]), "First transaction is not Coinbase.")

    txids = [transaction["txid"] for transaction in transactions]
    computed_merkle_internal, merkle_widths = merkle_root_from_display_hashes(txids)
    computed_merkle_root = computed_merkle_internal[::-1].hex()
    merkle_valid = computed_merkle_internal == merkle_raw

    coinbase_height = parse_coinbase_height(transactions[0])
    require(coinbase_height is not None, "Could not decode the BIP34 block height.")

    coinbase_pushes = analyze_coinbase_script_sig(transactions[0])
    coinbase_output_total_sat = sum(
        output["value_sat"] for output in transactions[0]["outputs"]
    )
    subsidy_sat = block_subsidy_sat(coinbase_height)
    claimed_fee_component_sat = coinbase_output_total_sat - subsidy_sat
    require(
        claimed_fee_component_sat >= 0,
        "Coinbase output total is lower than the scheduled subsidy.",
    )

    witness_commitment = verify_witness_commitment(transactions)

    getcontext().prec = 50
    difficulty = (
        Decimal(DIFFICULTY_ONE_TARGET) / Decimal(target_info["target"])
        if target_info["target"]
        else Decimal(0)
    )

    header_fields = [
        HeaderField(
            "version",
            0,
            4,
            version_raw.hex(),
            f"{version} (0x{version:08x})",
            "Block version, little-endian uint32.",
        ),
        HeaderField(
            "previous_block_hash",
            4,
            32,
            previous_raw.hex(),
            previous_block_hash,
            "Hash of the preceding block; serialized in reverse byte order.",
        ),
        HeaderField(
            "merkle_root",
            36,
            32,
            merkle_raw.hex(),
            header_merkle_root,
            "Merkle root committing to all transaction IDs.",
        ),
        HeaderField(
            "timestamp",
            68,
            4,
            timestamp_raw.hex(),
            f"{timestamp} ({format_timestamp(timestamp)})",
            "Unix block timestamp, little-endian uint32.",
        ),
        HeaderField(
            "nBits",
            72,
            4,
            bits_raw.hex(),
            f"0x{bits:08x}",
            "Compact proof-of-work target.",
        ),
        HeaderField(
            "nonce",
            76,
            4,
            nonce_raw.hex(),
            f"{nonce} (0x{nonce:08x})",
            "Mining nonce, little-endian uint32.",
        ),
        HeaderField(
            "transaction_count",
            count_offset,
            len(count_raw),
            count_raw.hex(),
            str(transaction_count),
            "Number of serialized transactions, CompactSize encoded.",
        ),
    ]

    return {
        "raw_size": len(raw),
        "header": header,
        "header_fields": header_fields,
        "version": version,
        "previous_block_hash": previous_block_hash,
        "header_merkle_root": header_merkle_root,
        "computed_merkle_root": computed_merkle_root,
        "merkle_valid": merkle_valid,
        "merkle_level_widths": merkle_widths,
        "timestamp": timestamp,
        "timestamp_utc": format_timestamp(timestamp),
        "bits": bits,
        "bits_hex": f"{bits:08x}",
        "nonce": nonce,
        "block_hash": block_hash,
        "block_hash_integer": block_hash_integer,
        "target": target_info["target"],
        "target_hex": target_info["target_hex"],
        "target_exponent": target_info["exponent"],
        "target_coefficient": target_info["coefficient"],
        "difficulty": difficulty,
        "pow_valid": pow_valid,
        "transaction_count": transaction_count,
        "transactions": transactions,
        "transaction_offsets": transaction_offsets,
        "coinbase_height": coinbase_height,
        "coinbase_pushes": coinbase_pushes,
        "coinbase_output_total_sat": coinbase_output_total_sat,
        "block_subsidy_sat": subsidy_sat,
        "claimed_fee_component_sat": claimed_fee_component_sat,
        "witness_commitment": witness_commitment,
        "end_offset": reader.offset,
    }


def project_checks(
    block: dict[str, Any],
    metadata: dict[str, Any],
    expected_transaction_raw: bytes,
) -> list[tuple[str, bool, str]]:
    checks: list[tuple[str, bool, str]] = []

    def add(name: str, actual: Any, expected: Any) -> None:
        checks.append(
            (
                name,
                actual == expected,
                f"actual={actual!r}, expected={expected!r}",
            )
        )

    expected_block_hash = (
        metadata.get("experiment_block_hash")
        or metadata.get("block_hash")
    )
    if expected_block_hash:
        add("Block hash matches metadata", block["block_hash"], expected_block_hash)

    expected_height = (
        metadata.get("experiment_block_height")
        if metadata.get("experiment_block_height") is not None
        else metadata.get("block_height")
    )
    if expected_height is not None:
        add("Coinbase BIP34 height", block["coinbase_height"], int(expected_height))

    expected_size = metadata.get("experiment_raw_block_size_bytes")
    if expected_size is not None:
        add("Raw block size", block["raw_size"], int(expected_size))

    expected_count = metadata.get("experiment_block_tx_count")
    if expected_count is not None:
        add("Block transaction count", block["transaction_count"], int(expected_count))

    experiment_txid = metadata.get("experiment_txid")
    if experiment_txid:
        matching_indices = [
            transaction["block_index"]
            for transaction in block["transactions"]
            if transaction["txid"] == experiment_txid
        ]
        expected_index = metadata.get("experiment_block_index")

        checks.append(
            (
                "Experiment TXID occurs exactly once",
                len(matching_indices) == 1,
                f"indices={matching_indices!r}",
            )
        )

        if matching_indices and expected_index is not None:
            add(
                "Experiment transaction index",
                matching_indices[0],
                int(expected_index),
            )

        if matching_indices:
            parsed_raw = bytes.fromhex(
                block["transactions"][matching_indices[0]]["raw_hex"]
            )
            checks.append(
                (
                    "Experiment transaction bytes match raw_transaction.hex",
                    parsed_raw == expected_transaction_raw,
                    f"parsed={len(parsed_raw)} bytes, "
                    f"file={len(expected_transaction_raw)} bytes",
                )
            )

    return checks


def print_transaction_list(block: dict[str, Any]) -> None:
    print()
    print("=" * 120)
    print("TRANSACTIONS IN BLOCK")
    print("=" * 120)
    print(
        f"{'Index':>5}  {'Offset':>10}  {'Size':>8}  "
        f"{'Witness':>8}  {'Inputs':>7}  {'Outputs':>8}  TXID"
    )
    print("-" * 120)

    for transaction, offset in zip(
        block["transactions"],
        block["transaction_offsets"],
    ):
        print(
            f"{transaction['block_index']:5d}  {offset:10d}  "
            f"{transaction['size']:8d}  "
            f"{str(transaction['has_witness']):>8}  "
            f"{transaction['input_count']:7d}  "
            f"{transaction['output_count']:8d}  "
            f"{transaction['txid']}"
        )

    print("-" * 120)


def print_transaction_offset_table(block: dict[str, Any]) -> None:
    """
    Print a compact table for appendix:
    transaction index, byte offset, serialized size and TXID.
    """
    print()
    print("=" * 100)
    print("TRANSACTION OFFSET TABLE")
    print("=" * 100)
    print(
        f"{'Index':>8}  {'Offset':>10}  "
        f"{'Size(bytes)':>12}  TXID"
    )
    print("-" * 100)

    for transaction, offset in zip(
        block["transactions"],
        block["transaction_offsets"],
    ):
        print(
            f"{transaction['block_index']:8d}  "
            f"{offset:10d}  "
            f"{transaction['size']:12d}  "
            f"{transaction['txid']}"
        )

    print("-" * 100)


def print_summary(
    block: dict[str, Any],
    metadata: dict[str, Any],
    expected_transaction_raw: bytes,
) -> None:
    print()
    print("=" * 92)
    print("BLOCK SUMMARY")
    print("=" * 92)
    print(f"Raw block size          : {block['raw_size']} bytes")
    print(f"Header size             : 80 bytes")
    print(f"Version                 : {block['version']} (0x{block['version']:08x})")
    print(f"Version bits            : {format_bits(block['version'], 32)}")
    print(f"Previous block hash     : {block['previous_block_hash']}")
    print(f"Timestamp               : {block['timestamp']} ({block['timestamp_utc']})")
    print(f"nBits                   : 0x{block['bits_hex']}")
    print(f"nBits bits              : {format_bits(block['bits'], 32)}")
    print(f"Nonce                   : {block['nonce']} (0x{block['nonce']:08x})")
    print(f"Nonce bits              : {format_bits(block['nonce'], 32)}")
    print(f"Transaction count       : {block['transaction_count']}")
    print(f"Coinbase BIP34 height   : {block['coinbase_height']}")
    print(f"All bytes consumed      : {block['end_offset'] == block['raw_size']}")

    print()
    print("=" * 92)
    print("MERKLE ROOT VERIFICATION")
    print("=" * 92)
    print(f"Header Merkle root      : {block['header_merkle_root']}")
    print(f"Computed Merkle root    : {block['computed_merkle_root']}")
    print(f"Merkle level widths     : {' -> '.join(map(str, block['merkle_level_widths']))}")
    print(f"Merkle root valid       : {block['merkle_valid']}")

    print()
    print("=" * 92)
    print("BLOCK HASH AND PROOF-OF-WORK")
    print("=" * 92)
    print(f"Computed block hash     : {block['block_hash']}")
    print(
        f"Target exponent         : {block['target_exponent']} "
        f"(0x{block['target_exponent']:02x})"
    )
    print(
        f"Exponent bits           : "
        f"{format_bits(block['target_exponent'], 8)}"
    )
    print(f"Target sign bit         : 0")
    print(f"Target coefficient      : 0x{block['target_coefficient']:06x}")
    print(
        f"Coefficient bits        : "
        f"{format_bits(block['target_coefficient'], 23)}"
    )
    print(f"Expanded target         : {block['target_hex']}")
    print(f"Block hash integer      : {block['block_hash_integer']}")
    print(f"Target integer          : {block['target']}")
    print(f"Target - hash           : {block['target'] - block['block_hash_integer']}")
    print(f"Difficulty              : {block['difficulty']}")
    print(f"Hash integer <= target  : {block['pow_valid']}")

    coinbase = block["transactions"][0]
    coinbase_input = coinbase["inputs"][0]

    print()
    print("=" * 92)
    print("COINBASE TRANSACTION")
    print("=" * 92)
    print(f"Coinbase TXID           : {coinbase['txid']}")
    print(f"Coinbase WTXID          : {coinbase['wtxid']}")
    print(f"Previous TXID           : {coinbase_input['previous_txid']}")
    print(
        f"Previous vout           : {coinbase_input['previous_vout']} "
        f"(0x{coinbase_input['previous_vout']:08x})"
    )
    print(f"Special Coinbase input  : {is_coinbase(coinbase)}")
    print(f"Coinbase height         : {block['coinbase_height']}")
    print(f"Coinbase scriptSig      : {coinbase_input['scriptSig_hex']}")

    for item in block["coinbase_pushes"]:
        print(f"  Push {item['index']}")
        print(f"    Opcode              : {item['opcode_name']}")
        print(f"    Length              : {item['length']} bytes")
        print(f"    Data                : {item['data_hex']}")
        print(f"    Role                : {item['role']}")
        if "script_number" in item:
            print(f"    Script number       : {item['script_number']}")
        if item["ascii"] is not None:
            print(f"    ASCII               : {item['ascii']}")

    print(f"Coinbase outputs        : {coinbase['output_count']}")
    print(
        f"Coinbase output total   : "
        f"{block['coinbase_output_total_sat']} sat"
    )
    print(f"Scheduled subsidy       : {block['block_subsidy_sat']} sat")
    print(
        f"Claimed fee component   : "
        f"{block['claimed_fee_component_sat']} sat"
    )
    if "experiment_fee_sat" in metadata:
        print(
            f"Experiment tx fee       : "
            f"{int(metadata['experiment_fee_sat'])} sat"
        )
    print(f"Coinbase witness items  : {len(coinbase_input['witness'])}")

    witness = block["witness_commitment"]
    print()
    print("=" * 92)
    print("WITNESS COMMITMENT")
    print("=" * 92)
    print(f"Commitment present      : {witness['present']}")
    if witness["present"]:
        print(f"Commitment output index : {witness.get('output_index')}")
        print(f"Committed hash          : {witness.get('committed_hash')}")
        print(f"Computed hash           : {witness.get('computed_hash')}")
        print(f"Reserved value          : {witness.get('reserved_value')}")
        print(f"Witness commitment valid: {witness.get('verified')}")
    else:
        print(f"Reason                  : {witness.get('reason')}")

    experiment_txid = metadata.get("experiment_txid")
    if experiment_txid:
        matches = [
            transaction
            for transaction in block["transactions"]
            if transaction["txid"] == experiment_txid
        ]
        print()
        print("=" * 92)
        print("EXPERIMENT TRANSACTION LOCATION")
        print("=" * 92)
        if matches:
            transaction = matches[0]
            print(f"TXID                    : {transaction['txid']}")
            print(f"Block index             : {transaction['block_index']}")
            print(f"Serialized size         : {transaction['size']} bytes")
            print(f"Inputs / outputs        : {transaction['input_count']} / {transaction['output_count']}")
        else:
            print("Experiment transaction was not found.")

    checks = project_checks(block, metadata, expected_transaction_raw)
    print()
    print("=" * 92)
    print("PROJECT CROSS-CHECKS")
    print("=" * 92)

    failures = 0
    for name, passed, detail in checks:
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {name}: {detail}")
        if not passed:
            failures += 1

    if failures:
        raise BlockParseError(f"{failures} project cross-check(s) failed.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Independently parse a raw Bitcoin block and verify its Merkle "
            "root, block hash, proof of work, and witness commitment."
        )
    )
    parser.add_argument(
        "block",
        nargs="?",
        type=Path,
        default=DEFAULT_BLOCK_PATH,
        help="Raw block hex file (default: data/raw_block.hex).",
    )
    parser.add_argument(
        "--transaction",
        type=Path,
        default=DEFAULT_TX_PATH,
        help="Experiment raw transaction used for byte-for-byte cross-check.",
    )
    parser.add_argument(
        "--metadata",
        type=Path,
        default=DEFAULT_METADATA_PATH,
        help="Project metadata JSON.",
    )
    parser.add_argument(
        "--no-transactions",
        action="store_true",
        help="Do not print the complete transaction index table.",
    )
    parser.add_argument(
        "--offset-table",
        action="store_true",
        help="Print compact transaction offset table for appendix.",
    )
    args = parser.parse_args()

    raw_block = read_hex(args.block)
    expected_transaction_raw = read_hex(args.transaction)
    metadata = load_metadata(args.metadata)

    block = parse_block(raw_block, network=str(metadata.get("network", "testnet4")))

    print(f"Input block file        : {args.block}")
    print(f"Raw serialized bytes    : {len(raw_block)}")

    print()
    print_header_table(block["header_fields"])

    if not args.no_transactions:
        print_transaction_list(block)

    print_summary(block, metadata, expected_transaction_raw)

    if args.offset_table:
        print_transaction_offset_table(block)

    require(block["merkle_valid"], "Computed Merkle root does not match header.")
    require(block["pow_valid"], "Block hash does not satisfy the target.")

    witness = block["witness_commitment"]
    if witness["present"]:
        require(
            witness.get("verified") is True,
            "Witness commitment is present but invalid.",
        )

    print()
    print("=" * 92)
    print("FINAL RESULT")
    print("=" * 92)
    print("[PASS] The complete block was parsed without gaps or trailing data.")
    print("[PASS] Every transaction TXID/WTXID was recomputed from raw bytes.")
    print("[PASS] The transaction Merkle root matches the 80-byte block header.")
    print("[PASS] The independently computed block hash matches project metadata.")
    print("[PASS] nBits was expanded and the proof-of-work inequality is satisfied.")
    if witness["present"]:
        print("[PASS] The SegWit witness commitment is valid.")
    else:
        print("[PASS] No witness commitment was required/present in this block.")
    print(
        "[PASS] The Coinbase special input, BIP34 height, miner-defined data, "
        "scheduled subsidy, and claimed fee component were analyzed."
    )
    print("[PASS] The experiment transaction was located and matched byte-for-byte.")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BlockParseError, TransactionParseError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
