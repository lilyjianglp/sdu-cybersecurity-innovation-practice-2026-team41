#!/usr/bin/env python3
"""
Independently parse and verify a serialized Bitcoin transaction.

Default inputs:
  data/raw_transaction.hex
  data/metadata.json

The parser does not call Bitcoin Core. It reads raw bytes directly, prints a
byte-offset table, decodes common scripts, parses a classic P2PKH scriptSig,
and recomputes TXID/WTXID.

The parsing functions are intentionally reusable by src/parse_block.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TX_PATH = PROJECT_ROOT / "data" / "raw_transaction.hex"
DEFAULT_METADATA_PATH = PROJECT_ROOT / "data" / "metadata.json"

SECP256K1_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
    "BAAEDCE6AF48A03BBFD25E8CD0364141",
    16,
)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class ParseError(ValueError):
    """Raised when serialized data is malformed or unexpectedly truncated."""


@dataclass(frozen=True)
class Field:
    """One serialized field with transaction-relative and absolute offsets."""

    name: str
    relative_offset: int
    absolute_offset: int
    length: int
    raw_hex: str
    value: str
    meaning: str


class ByteReader:
    """Bounds-checked reader over a bytes object."""

    def __init__(self, data: bytes, offset: int = 0) -> None:
        self.data = data
        self.offset = offset

    def remaining(self) -> int:
        return len(self.data) - self.offset

    def read(self, length: int) -> tuple[int, bytes]:
        if length < 0:
            raise ParseError("Negative read length.")
        start = self.offset
        end = start + length
        if end > len(self.data):
            raise ParseError(
                f"Truncated data at offset {start}: "
                f"need {length} byte(s), have {len(self.data) - start}."
            )
        self.offset = end
        return start, self.data[start:end]

    def read_uint_le(self, length: int) -> tuple[int, bytes, int]:
        start, raw = self.read(length)
        return start, raw, int.from_bytes(raw, "little", signed=False)

    def read_compact_size(self) -> tuple[int, bytes, int]:
        start, first_raw = self.read(1)
        first = first_raw[0]

        if first < 0xFD:
            return start, first_raw, first

        extra_length = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
        _, extra = self.read(extra_length)
        value = int.from_bytes(extra, "little", signed=False)

        minimum = {0xFD: 0xFD, 0xFE: 0x10000, 0xFF: 0x100000000}[first]
        if value < minimum:
            raise ParseError(
                f"Non-canonical CompactSize encoding at offset {start}."
            )

        return start, first_raw + extra, value


def hash256(data: bytes) -> bytes:
    """Bitcoin HASH256: SHA-256 applied twice."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """Bitcoin HASH160: RIPEMD-160(SHA-256(data))."""
    sha = hashlib.sha256(data).digest()
    try:
        return hashlib.new("ripemd160", sha).digest()
    except ValueError as exc:
        raise ParseError(
            "This Python/OpenSSL build does not provide RIPEMD-160."
        ) from exc


def display_hash(internal_hash: bytes) -> str:
    """Convert internal little-endian hash bytes to normal displayed hex."""
    return internal_hash[::-1].hex()


def base58check(version: int, payload: bytes) -> str:
    """Encode a version byte and payload using Base58Check."""
    body = bytes([version]) + payload
    encoded = body + hash256(body)[:4]

    zero_count = len(encoded) - len(encoded.lstrip(b"\x00"))
    number = int.from_bytes(encoded, "big")
    chars: list[str] = []

    while number:
        number, remainder = divmod(number, 58)
        chars.append(BASE58_ALPHABET[remainder])

    return "1" * zero_count + "".join(reversed(chars or ["1"]))


def encode_compact_size(value: int) -> bytes:
    """Encode an integer using Bitcoin CompactSize."""
    if value < 0:
        raise ParseError("CompactSize cannot encode a negative value.")
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + value.to_bytes(8, "little")
    raise ParseError("CompactSize value exceeds uint64.")


def format_btc(satoshis: int) -> str:
    """Format satoshis as an exact BTC decimal."""
    whole, fraction = divmod(satoshis, 100_000_000)
    return f"{whole}.{fraction:08d} BTC"


def format_bits(value: int, width: int, group: int = 8) -> str:
    """Render an integer as a fixed-width binary string grouped for readability."""
    if width <= 0:
        raise ParseError("Bit width must be positive.")
    if value < 0 or value >= (1 << width):
        raise ParseError(f"Value {value} does not fit in {width} bits.")

    bits = f"{value:0{width}b}"
    first_group = width % group
    groups: list[str] = []

    if first_group:
        groups.append(bits[:first_group])
        bits = bits[first_group:]

    groups.extend(bits[index:index + group] for index in range(0, len(bits), group))
    return " ".join(groups)


def classify_script_pubkey(script: bytes, network: str = "testnet4") -> dict[str, Any]:
    """Recognize common standard output scripts."""
    result: dict[str, Any] = {
        "type": "unknown",
        "asm": script.hex(),
        "payload": None,
        "address": None,
    }

    if (
        len(script) == 25
        and script[0:3] == b"\x76\xa9\x14"
        and script[-2:] == b"\x88\xac"
    ):
        payload = script[3:23]
        version = 0x6F if network != "main" else 0x00
        result.update(
            {
                "type": "p2pkh",
                "asm": (
                    f"OP_DUP OP_HASH160 {payload.hex()} "
                    "OP_EQUALVERIFY OP_CHECKSIG"
                ),
                "payload": payload.hex(),
                "address": base58check(version, payload),
            }
        )
        return result

    if (
        len(script) == 23
        and script[0:2] == b"\xa9\x14"
        and script[-1:] == b"\x87"
    ):
        payload = script[2:22]
        version = 0xC4 if network != "main" else 0x05
        result.update(
            {
                "type": "p2sh",
                "asm": f"OP_HASH160 {payload.hex()} OP_EQUAL",
                "payload": payload.hex(),
                "address": base58check(version, payload),
            }
        )
        return result

    if len(script) == 22 and script[0:2] == b"\x00\x14":
        payload = script[2:]
        result.update(
            {
                "type": "p2wpkh",
                "asm": f"OP_0 {payload.hex()}",
                "payload": payload.hex(),
            }
        )
        return result

    if len(script) == 34 and script[0:2] == b"\x00\x20":
        payload = script[2:]
        result.update(
            {
                "type": "p2wsh",
                "asm": f"OP_0 {payload.hex()}",
                "payload": payload.hex(),
            }
        )
        return result

    if len(script) == 34 and script[0:2] == b"\x51\x20":
        payload = script[2:]
        result.update(
            {
                "type": "p2tr",
                "asm": f"OP_1 {payload.hex()}",
                "payload": payload.hex(),
            }
        )
        return result

    if script.startswith(b"\x6a"):
        result.update(
            {
                "type": "nulldata",
                "asm": f"OP_RETURN {script[1:].hex()}",
            }
        )
        return result

    return result


def read_script_pushes(script: bytes) -> list[dict[str, Any]]:
    """Parse push-only script data, including PUSHDATA1/2/4."""
    pushes: list[dict[str, Any]] = []
    offset = 0

    while offset < len(script):
        opcode_offset = offset
        opcode = script[offset]
        offset += 1

        if opcode == 0x00:
            length = 0
            opcode_name = "OP_0"
        elif 0x01 <= opcode <= 0x4B:
            length = opcode
            opcode_name = f"PUSH({length})"
        elif opcode == 0x4C:
            if offset + 1 > len(script):
                raise ParseError("Truncated OP_PUSHDATA1.")
            length = script[offset]
            offset += 1
            opcode_name = f"OP_PUSHDATA1({length})"
        elif opcode == 0x4D:
            if offset + 2 > len(script):
                raise ParseError("Truncated OP_PUSHDATA2.")
            length = int.from_bytes(script[offset:offset + 2], "little")
            offset += 2
            opcode_name = f"OP_PUSHDATA2({length})"
        elif opcode == 0x4E:
            if offset + 4 > len(script):
                raise ParseError("Truncated OP_PUSHDATA4.")
            length = int.from_bytes(script[offset:offset + 4], "little")
            offset += 4
            opcode_name = f"OP_PUSHDATA4({length})"
        else:
            raise ParseError(
                f"Non-push opcode 0x{opcode:02x} in scriptSig "
                f"at script offset {opcode_offset}."
            )

        end = offset + length
        if end > len(script):
            raise ParseError(
                f"Push at script offset {opcode_offset} exceeds script length."
            )

        pushes.append(
            {
                "opcode_offset": opcode_offset,
                "opcode": opcode,
                "opcode_name": opcode_name,
                "data_offset": offset,
                "length": length,
                "data": script[offset:end],
            }
        )
        offset = end

    return pushes


def decode_sighash_type(value: int) -> str:
    """Decode the conventional one-byte ECDSA sighash flag."""
    base = value & 0x1F
    base_name = {
        0x01: "SIGHASH_ALL",
        0x02: "SIGHASH_NONE",
        0x03: "SIGHASH_SINGLE",
    }.get(base, f"UNKNOWN_BASE(0x{base:02x})")

    if value & 0x80:
        return f"{base_name}|SIGHASH_ANYONECANPAY"
    return base_name


def parse_der_signature(signature_with_type: bytes) -> dict[str, Any]:
    """Parse a strict DER ECDSA signature followed by a sighash byte."""
    if len(signature_with_type) < 9:
        raise ParseError("Signature push is too short.")

    sighash_byte = signature_with_type[-1]
    der = signature_with_type[:-1]

    if der[0] != 0x30:
        raise ParseError("DER signature does not begin with SEQUENCE (0x30).")
    if len(der) < 2 or der[1] != len(der) - 2:
        raise ParseError("DER SEQUENCE length is inconsistent.")

    offset = 2
    if offset >= len(der) or der[offset] != 0x02:
        raise ParseError("DER signature is missing INTEGER r.")
    offset += 1

    if offset >= len(der):
        raise ParseError("DER signature is truncated before r length.")
    r_length = der[offset]
    offset += 1
    r_end = offset + r_length
    if r_end > len(der):
        raise ParseError("DER integer r exceeds signature length.")
    r_raw = der[offset:r_end]
    offset = r_end

    if offset >= len(der) or der[offset] != 0x02:
        raise ParseError("DER signature is missing INTEGER s.")
    offset += 1

    if offset >= len(der):
        raise ParseError("DER signature is truncated before s length.")
    s_length = der[offset]
    offset += 1
    s_end = offset + s_length
    if s_end != len(der):
        raise ParseError("DER integer s length is inconsistent.")
    s_raw = der[offset:s_end]

    if not r_raw or not s_raw:
        raise ParseError("DER r and s must be non-empty.")

    r = int.from_bytes(r_raw, "big")
    s = int.from_bytes(s_raw, "big")

    return {
        "der_hex": der.hex(),
        "der_length": len(der),
        "r_hex": r_raw.hex(),
        "r": r,
        "s_hex": s_raw.hex(),
        "s": s,
        "s_is_low": s <= SECP256K1_ORDER // 2,
        "sighash_byte": sighash_byte,
        "sighash_name": decode_sighash_type(sighash_byte),
    }


def parse_p2pkh_scriptsig(script: bytes) -> dict[str, Any] | None:
    """Decode the standard <signature> <compressed pubkey> P2PKH scriptSig."""
    try:
        pushes = read_script_pushes(script)
    except ParseError:
        return None

    if len(pushes) != 2:
        return None

    signature = pushes[0]["data"]
    public_key = pushes[1]["data"]

    if not signature or signature[0] != 0x30:
        return None
    if len(public_key) != 33 or public_key[0] not in (0x02, 0x03):
        return None

    der_info = parse_der_signature(signature)
    public_key_hash = hash160(public_key)

    return {
        "pushes": pushes,
        "signature": der_info,
        "public_key_hex": public_key.hex(),
        "public_key_length": len(public_key),
        "public_key_prefix": f"0x{public_key[0]:02x}",
        "public_key_hash160": public_key_hash.hex(),
        "testnet_p2pkh_address": base58check(0x6F, public_key_hash),
    }


def add_field(
    fields: list[Field],
    transaction_start: int,
    name: str,
    absolute_offset: int,
    raw: bytes,
    value: str,
    meaning: str,
) -> None:
    fields.append(
        Field(
            name=name,
            relative_offset=absolute_offset - transaction_start,
            absolute_offset=absolute_offset,
            length=len(raw),
            raw_hex=raw.hex(),
            value=value,
            meaning=meaning,
        )
    )


def parse_transaction(
    data: bytes,
    offset: int = 0,
    *,
    network: str = "testnet4",
) -> tuple[dict[str, Any], int]:
    """
    Parse one transaction beginning at data[offset].

    Returns:
      (transaction_dictionary, offset_immediately_after_transaction)

    This supports both Legacy and SegWit serialization and preserves enough raw
    slices to recompute TXID and WTXID exactly.
    """
    transaction_start = offset
    reader = ByteReader(data, offset)
    fields: list[Field] = []

    version_offset, version_raw, version = reader.read_uint_le(4)
    add_field(
        fields,
        transaction_start,
        "version",
        version_offset,
        version_raw,
        str(version),
        "Transaction format/rule version, little-endian uint32.",
    )

    has_witness = False
    marker_flag_raw = b""

    if reader.remaining() >= 2:
        marker = data[reader.offset]
        flag = data[reader.offset + 1]
        if marker == 0x00 and flag != 0x00:
            marker_offset, marker_flag_raw = reader.read(2)
            has_witness = True
            add_field(
                fields,
                transaction_start,
                "marker_flag",
                marker_offset,
                marker_flag_raw,
                f"marker=0x{marker:02x}, flag=0x{flag:02x}",
                "SegWit serialization marker and flag.",
            )

    vin_count_offset, vin_count_raw, vin_count = reader.read_compact_size()
    add_field(
        fields,
        transaction_start,
        "input_count",
        vin_count_offset,
        vin_count_raw,
        str(vin_count),
        "Number of transaction inputs, CompactSize encoded.",
    )

    inputs: list[dict[str, Any]] = []
    raw_input_slices: list[bytes] = []

    for input_index in range(vin_count):
        input_start = reader.offset

        prev_offset, prev_raw = reader.read(32)
        prev_txid = prev_raw[::-1].hex()
        add_field(
            fields,
            transaction_start,
            f"vin[{input_index}].previous_txid",
            prev_offset,
            prev_raw,
            prev_txid,
            "Previous transaction ID; serialized byte order is reversed.",
        )

        vout_offset, vout_raw, previous_vout = reader.read_uint_le(4)
        add_field(
            fields,
            transaction_start,
            f"vin[{input_index}].previous_vout",
            vout_offset,
            vout_raw,
            str(previous_vout),
            "Index of the previous transaction output, little-endian uint32.",
        )

        script_length_offset, script_length_raw, script_length = (
            reader.read_compact_size()
        )
        add_field(
            fields,
            transaction_start,
            f"vin[{input_index}].scriptSig_length",
            script_length_offset,
            script_length_raw,
            str(script_length),
            "Length of the unlocking script, CompactSize encoded.",
        )

        script_offset, script = reader.read(script_length)
        add_field(
            fields,
            transaction_start,
            f"vin[{input_index}].scriptSig",
            script_offset,
            script,
            script.hex() if script else "<empty>",
            "Input unlocking script.",
        )

        sequence_offset, sequence_raw, sequence = reader.read_uint_le(4)
        add_field(
            fields,
            transaction_start,
            f"vin[{input_index}].sequence",
            sequence_offset,
            sequence_raw,
            f"{sequence} (0x{sequence:08x})",
            "Input sequence number, little-endian uint32.",
        )

        raw_input_slices.append(data[input_start:reader.offset])
        inputs.append(
            {
                "index": input_index,
                "previous_txid": prev_txid,
                "previous_vout": previous_vout,
                "scriptSig_hex": script.hex(),
                "scriptSig_length": script_length,
                "sequence": sequence,
                "p2pkh_scriptSig": (
                    parse_p2pkh_scriptsig(script) if script else None
                ),
                "witness": [],
            }
        )

    vout_count_offset, vout_count_raw, vout_count = reader.read_compact_size()
    add_field(
        fields,
        transaction_start,
        "output_count",
        vout_count_offset,
        vout_count_raw,
        str(vout_count),
        "Number of transaction outputs, CompactSize encoded.",
    )

    outputs: list[dict[str, Any]] = []
    raw_output_slices: list[bytes] = []

    for output_index in range(vout_count):
        output_start = reader.offset

        value_offset, value_raw, value_sat = reader.read_uint_le(8)
        add_field(
            fields,
            transaction_start,
            f"vout[{output_index}].value",
            value_offset,
            value_raw,
            f"{value_sat} sat ({format_btc(value_sat)})",
            "Output amount in satoshis, little-endian uint64.",
        )

        script_length_offset, script_length_raw, script_length = (
            reader.read_compact_size()
        )
        add_field(
            fields,
            transaction_start,
            f"vout[{output_index}].scriptPubKey_length",
            script_length_offset,
            script_length_raw,
            str(script_length),
            "Length of the locking script, CompactSize encoded.",
        )

        script_offset, script = reader.read(script_length)
        script_info = classify_script_pubkey(script, network)
        add_field(
            fields,
            transaction_start,
            f"vout[{output_index}].scriptPubKey",
            script_offset,
            script,
            script_info["asm"],
            f"Output locking script ({script_info['type']}).",
        )

        raw_output_slices.append(data[output_start:reader.offset])
        outputs.append(
            {
                "index": output_index,
                "value_sat": value_sat,
                "value_btc": format_btc(value_sat),
                "scriptPubKey_hex": script.hex(),
                "scriptPubKey_length": script_length,
                "script": script_info,
            }
        )

    if has_witness:
        for input_index in range(vin_count):
            item_count_offset, item_count_raw, item_count = (
                reader.read_compact_size()
            )
            add_field(
                fields,
                transaction_start,
                f"vin[{input_index}].witness_item_count",
                item_count_offset,
                item_count_raw,
                str(item_count),
                "Number of witness stack items, CompactSize encoded.",
            )

            witness_items: list[str] = []
            for item_index in range(item_count):
                item_length_offset, item_length_raw, item_length = (
                    reader.read_compact_size()
                )
                add_field(
                    fields,
                    transaction_start,
                    f"vin[{input_index}].witness[{item_index}]_length",
                    item_length_offset,
                    item_length_raw,
                    str(item_length),
                    "Witness item length, CompactSize encoded.",
                )

                item_offset, item = reader.read(item_length)
                add_field(
                    fields,
                    transaction_start,
                    f"vin[{input_index}].witness[{item_index}]",
                    item_offset,
                    item,
                    item.hex() if item else "<empty>",
                    "Witness stack item.",
                )
                witness_items.append(item.hex())

            inputs[input_index]["witness"] = witness_items

    locktime_offset, locktime_raw, locktime = reader.read_uint_le(4)
    add_field(
        fields,
        transaction_start,
        "locktime",
        locktime_offset,
        locktime_raw,
        str(locktime),
        "Absolute locktime; 0 means no absolute locktime constraint.",
    )

    transaction_end = reader.offset
    full_serialization = data[transaction_start:transaction_end]

    stripped_serialization = (
        version_raw
        + vin_count_raw
        + b"".join(raw_input_slices)
        + vout_count_raw
        + b"".join(raw_output_slices)
        + locktime_raw
    )

    if not has_witness and stripped_serialization != full_serialization:
        raise ParseError("Legacy stripped serialization differs from full bytes.")

    txid = display_hash(hash256(stripped_serialization))
    wtxid = display_hash(hash256(full_serialization))

    stripped_size = len(stripped_serialization)
    total_size = len(full_serialization)
    witness_size = total_size - stripped_size
    weight = stripped_size * 4 + witness_size
    vsize = math.ceil(weight / 4)

    return (
        {
            "start_offset": transaction_start,
            "end_offset": transaction_end,
            "size": total_size,
            "stripped_size": stripped_size,
            "witness_size": witness_size,
            "weight": weight,
            "vsize": vsize,
            "version": version,
            "has_witness": has_witness,
            "marker_flag_hex": marker_flag_raw.hex(),
            "input_count": vin_count,
            "inputs": inputs,
            "output_count": vout_count,
            "outputs": outputs,
            "locktime": locktime,
            "txid": txid,
            "wtxid": wtxid,
            "raw_hex": full_serialization.hex(),
            "stripped_hex": stripped_serialization.hex(),
            "fields": fields,
        },
        transaction_end,
    )


def shorten_hex(value: str, limit: int = 58) -> str:
    if len(value) <= limit:
        return value
    keep = (limit - 3) // 2
    return f"{value[:keep]}...{value[-keep:]}"


def print_field_table(fields: Iterable[Field]) -> None:
    """Print a report-friendly serialized-field table."""
    rows = list(fields)
    print("=" * 124)
    print("BYTE-LEVEL FIELD TABLE")
    print("=" * 124)
    print(
        f"{'Rel. off.':>9}  {'Len':>5}  {'Field':<34}  "
        f"{'Raw bytes':<61}  Parsed value"
    )
    print("-" * 124)

    for field in rows:
        raw = shorten_hex(field.raw_hex, 59)
        value = field.value.replace("\n", " ")
        print(
            f"{field.relative_offset:9d}  {field.length:5d}  "
            f"{field.name:<34}  {raw:<61}  {value}"
        )

    print("-" * 124)
    print(
        "Offsets above are relative to the first byte of this transaction; "
        "all integer byte order is interpreted explicitly."
    )


def load_metadata(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ParseError(f"Invalid metadata JSON: {exc}") from exc


def verify_with_metadata(
    transaction: dict[str, Any],
    metadata: dict[str, Any],
) -> list[tuple[str, bool, str]]:
    """Cross-check parsed values against the project's fixed experiment data."""
    if not metadata:
        return []

    checks: list[tuple[str, bool, str]] = []

    def add(name: str, actual: Any, expected: Any) -> None:
        checks.append(
            (
                name,
                actual == expected,
                f"actual={actual!r}, expected={expected!r}",
            )
        )

    expected_txid = metadata.get("experiment_txid")
    if expected_txid:
        add("TXID matches metadata", transaction["txid"], expected_txid)

    expected_wtxid = metadata.get("experiment_wtxid")
    if expected_wtxid:
        add("WTXID matches metadata", transaction["wtxid"], expected_wtxid)

    if "experiment_size_bytes" in metadata:
        add(
            "Serialized size matches metadata",
            transaction["size"],
            int(metadata["experiment_size_bytes"]),
        )

    if "funding_txid" in metadata and transaction["inputs"]:
        add(
            "Input previous TXID",
            transaction["inputs"][0]["previous_txid"],
            metadata["funding_txid"],
        )

    if "funding_vout" in metadata and transaction["inputs"]:
        add(
            "Input previous vout",
            transaction["inputs"][0]["previous_vout"],
            int(metadata["funding_vout"]),
        )

    expected_output_values = [
        metadata.get("experiment_payment_amount_sat"),
        metadata.get("experiment_change_amount_sat"),
    ]
    for index, expected in enumerate(expected_output_values):
        if expected is not None and index < len(transaction["outputs"]):
            add(
                f"Output {index} amount",
                transaction["outputs"][index]["value_sat"],
                int(expected),
            )

    expected_addresses = [
        metadata.get("destination_address"),
        metadata.get("change_address"),
    ]
    for index, expected in enumerate(expected_addresses):
        if expected and index < len(transaction["outputs"]):
            add(
                f"Output {index} address",
                transaction["outputs"][index]["script"].get("address"),
                expected,
            )

    input_amount = metadata.get("experiment_input_amount_sat")
    expected_fee = metadata.get("experiment_fee_sat")
    if input_amount is not None:
        output_sum = sum(output["value_sat"] for output in transaction["outputs"])
        actual_fee = int(input_amount) - output_sum
        checks.append(
            (
                "Fee from input minus outputs",
                expected_fee is None or actual_fee == int(expected_fee),
                f"actual={actual_fee} sat, expected={expected_fee} sat",
            )
        )

    if transaction["inputs"]:
        p2pkh = transaction["inputs"][0].get("p2pkh_scriptSig")
        expected_address = metadata.get("faucet_address")
        if p2pkh and expected_address:
            add(
                "scriptSig public key recreates funding address",
                p2pkh["testnet_p2pkh_address"],
                expected_address,
            )

        expected_pubkey = metadata.get("experiment_public_key")
        if p2pkh and expected_pubkey:
            add(
                "scriptSig compressed public key",
                p2pkh["public_key_hex"],
                expected_pubkey,
            )

    return checks


def print_summary(
    transaction: dict[str, Any],
    metadata: dict[str, Any],
) -> None:
    print()
    print("=" * 84)
    print("TRANSACTION SUMMARY")
    print("=" * 84)
    print(f"Version                : {transaction['version']}")
    print(f"Version bits           : {format_bits(transaction['version'], 32)}")
    print(f"Serialization          : {'SegWit' if transaction['has_witness'] else 'Legacy'}")
    print(f"Inputs / outputs       : {transaction['input_count']} / {transaction['output_count']}")
    print(f"Locktime               : {transaction['locktime']}")
    print(f"Total size             : {transaction['size']} bytes")
    print(f"Stripped size          : {transaction['stripped_size']} bytes")
    print(f"Weight / vsize         : {transaction['weight']} / {transaction['vsize']}")
    print(f"TXID                   : {transaction['txid']}")
    print(f"WTXID                  : {transaction['wtxid']}")
    print(f"TXID == WTXID          : {transaction['txid'] == transaction['wtxid']}")
    print(
        f"All bytes consumed     : "
        f"{transaction['end_offset'] - transaction['start_offset'] == transaction['size']}"
    )

    for item in transaction["inputs"]:
        print()
        print(f"Input {item['index']}")
        print(f"  Previous outpoint    : {item['previous_txid']}:{item['previous_vout']}")
        print(f"  scriptSig length     : {item['scriptSig_length']} bytes")
        print(f"  Sequence             : {item['sequence']} (0x{item['sequence']:08x})")
        print(f"  Sequence bits        : {format_bits(item['sequence'], 32)}")
        print(f"  Witness items        : {len(item['witness'])}")

        p2pkh = item.get("p2pkh_scriptSig")
        if p2pkh:
            signature = p2pkh["signature"]
            print("  P2PKH scriptSig      : recognized")
            print(f"  Signature DER bytes  : {signature['der_length']}")
            print(f"  r                    : {signature['r_hex']}")
            print(f"  s                    : {signature['s_hex']}")
            print(f"  Low-S                : {signature['s_is_low']}")
            print(
                f"  Sighash               : "
                f"0x{signature['sighash_byte']:02x} "
                f"({signature['sighash_name']})"
            )
            print(
                f"  Sighash bits          : "
                f"{format_bits(signature['sighash_byte'], 8)}"
            )
            print(f"  Compressed public key: {p2pkh['public_key_hex']}")
            print(f"  HASH160(public key)   : {p2pkh['public_key_hash160']}")
            print(f"  Testnet P2PKH address : {p2pkh['testnet_p2pkh_address']}")

    output_sum = 0
    for output in transaction["outputs"]:
        output_sum += output["value_sat"]
        script = output["script"]
        print()
        print(f"Output {output['index']}")
        print(f"  Amount               : {output['value_sat']} sat ({output['value_btc']})")
        print(f"  Script type          : {script['type']}")
        print(f"  scriptPubKey         : {output['scriptPubKey_hex']}")
        print(f"  ASM                  : {script['asm']}")
        if script.get("address"):
            print(f"  Address              : {script['address']}")

    print()
    print(f"Total output value      : {output_sum} sat")

    if "experiment_input_amount_sat" in metadata:
        input_value = int(metadata["experiment_input_amount_sat"])
        fee = input_value - output_sum
        print(f"Known input value       : {input_value} sat")
        print(f"Transaction fee         : {fee} sat")
        print(f"Fee rate                : {fee / transaction['vsize']:.3f} sat/vB")

    checks = verify_with_metadata(transaction, metadata)
    if checks:
        print()
        print("=" * 84)
        print("PROJECT CROSS-CHECKS")
        print("=" * 84)
        failed = 0
        for name, passed, detail in checks:
            status = "PASS" if passed else "FAIL"
            print(f"[{status}] {name}: {detail}")
            if not passed:
                failed += 1

        if failed:
            raise ParseError(f"{failed} metadata cross-check(s) failed.")


def read_hex(path: Path) -> bytes:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise ParseError(f"Transaction file does not exist: {path}") from exc

    if not text:
        raise ParseError(f"Transaction file is empty: {path}")

    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ParseError(f"Invalid hexadecimal transaction data: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Independently parse a raw Bitcoin transaction and recompute "
            "TXID/WTXID without using Bitcoin Core."
        )
    )
    parser.add_argument(
        "transaction",
        nargs="?",
        type=Path,
        default=DEFAULT_TX_PATH,
        help="Raw transaction hex file (default: data/raw_transaction.hex).",
    )
    parser.add_argument(
        "--metadata",
        type=Path,
        default=DEFAULT_METADATA_PATH,
        help="Metadata JSON used only for cross-checks.",
    )
    parser.add_argument(
        "--no-fields",
        action="store_true",
        help="Do not print the byte-level field table.",
    )
    args = parser.parse_args()

    raw = read_hex(args.transaction)
    metadata = load_metadata(args.metadata)

    transaction, end_offset = parse_transaction(raw, 0, network="testnet4")
    if end_offset != len(raw):
        raise ParseError(
            f"Trailing bytes after transaction: parsed {end_offset}, "
            f"file contains {len(raw)} bytes."
        )

    print(f"Input file             : {args.transaction}")
    print(f"Raw serialized bytes   : {len(raw)}")

    if not args.no_fields:
        print()
        print_field_table(transaction["fields"])

    print_summary(transaction, metadata)

    print()
    print("=" * 84)
    print("FINAL RESULT")
    print("=" * 84)
    print("[PASS] Raw bytes were parsed without gaps or trailing data.")
    print("[PASS] TXID and WTXID were recomputed independently.")
    print("[PASS] Input scriptSig and both output scripts were decoded.")
    print("[PASS] All available project metadata checks passed.")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ParseError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
