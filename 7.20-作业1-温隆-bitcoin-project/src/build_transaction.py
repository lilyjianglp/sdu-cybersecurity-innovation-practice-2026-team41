#!/usr/bin/env python3
"""Build, sign, and preflight-check the course Bitcoin Testnet4 transaction.

This program NEVER broadcasts the transaction.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any

SATOSHIS_PER_BTC = Decimal("100000000")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
METADATA_PATH = PROJECT_ROOT / "data" / "metadata.json"
UNSIGNED_PATH = PROJECT_ROOT / "data" / "unsigned_transaction.hex"
SIGNED_PATH = PROJECT_ROOT / "data" / "raw_transaction.hex"


class BuildTransactionError(RuntimeError):
    pass


def btc_to_sat(value: Any) -> int:
    return int((Decimal(str(value)) * SATOSHIS_PER_BTC).to_integral_exact())


def sat_to_btc_string(value: int) -> str:
    return f"{Decimal(value) / SATOSHIS_PER_BTC:.8f}"


def rpc(method: str, *params: Any, wallet: str | None = None) -> Any:
    command = ["bitcoin-cli", "-testnet4"]
    if wallet is not None:
        command.append(f"-rpcwallet={wallet}")
    command.append(method)

    for param in params:
        if isinstance(param, (list, dict)):
            command.append(json.dumps(param, separators=(",", ":")))
        elif isinstance(param, bool):
            command.append("true" if param else "false")
        elif param is None:
            command.append("null")
        else:
            command.append(str(param))

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise BuildTransactionError(
            f"RPC {method!r} failed.\nCommand: {' '.join(command)}\n{detail}"
        )

    output = result.stdout.strip()
    if not output:
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return output


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildTransactionError(message)


def read_direct_push(script: bytes, offset: int) -> tuple[bytes, int]:
    if offset >= len(script):
        raise BuildTransactionError("Unexpected end of scriptSig.")
    length = script[offset]
    offset += 1
    if not 1 <= length <= 75:
        raise BuildTransactionError(
            f"Expected direct data push, got opcode 0x{length:02x}."
        )
    end = offset + length
    if end > len(script):
        raise BuildTransactionError("scriptSig push exceeds script length.")
    return script[offset:end], end


def load_metadata() -> dict[str, Any]:
    if not METADATA_PATH.exists():
        raise BuildTransactionError(f"Missing metadata file: {METADATA_PATH}")
    try:
        return json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BuildTransactionError(f"Invalid metadata JSON: {exc}") from exc


def main() -> int:
    metadata = load_metadata()

    wallet_name = str(metadata["wallet_name"])
    funding_txid = str(metadata["funding_txid"])
    funding_vout = int(metadata["funding_vout"])
    funding_amount_sat = int(metadata["funding_amount_sat"])
    funding_script = str(metadata["faucet_script_pubkey"])

    destination_address = str(metadata["destination_address"])
    change_address = str(metadata["change_address"])
    payment_sat = int(metadata["experiment_payment_amount_sat"])
    change_sat = int(metadata["experiment_change_amount_sat"])
    expected_fee_sat = int(metadata["experiment_fee_sat"])

    # 1. Node, wallet, and UTXO checks.
    chain_info = rpc("getblockchaininfo")
    require(isinstance(chain_info, dict), "Invalid getblockchaininfo result.")
    require(chain_info.get("chain") == "testnet4", "Node is not on Testnet4.")
    require(
        chain_info.get("initialblockdownload") is False,
        "Node is still in initial block download.",
    )

    wallets = rpc("listwallets")
    require(
        isinstance(wallets, list) and wallet_name in wallets,
        f"Wallet {wallet_name!r} is not loaded.",
    )

    utxo = rpc("gettxout", funding_txid, funding_vout, True)
    require(
        isinstance(utxo, dict),
        "Funding UTXO is unavailable or already spent. Nothing was written.",
    )
    require(
        btc_to_sat(utxo["value"]) == funding_amount_sat,
        "Funding amount does not match metadata.",
    )
    require(
        utxo["scriptPubKey"]["hex"] == funding_script,
        "Funding scriptPubKey does not match metadata.",
    )
    require(
        funding_amount_sat == payment_sat + change_sat + expected_fee_sat,
        "Amount conservation failed.",
    )

    # 2. Create unsigned version-2 Legacy transaction.
    inputs = [{
        "txid": funding_txid,
        "vout": funding_vout,
        "sequence": 4294967294,  # 0xfffffffe, non-RBF
    }]
    outputs = [
        {destination_address: sat_to_btc_string(payment_sat)},
        {change_address: sat_to_btc_string(change_sat)},
    ]

    unsigned_hex = rpc("createrawtransaction", inputs, outputs, 0, False, 2)
    require(isinstance(unsigned_hex, str) and unsigned_hex, "Empty unsigned hex.")
    try:
        bytes.fromhex(unsigned_hex)
    except ValueError as exc:
        raise BuildTransactionError(f"Invalid unsigned transaction hex: {exc}")

    unsigned = rpc("decoderawtransaction", unsigned_hex, False)
    require(isinstance(unsigned, dict), "Could not decode unsigned transaction.")
    require(unsigned["version"] == 2, "Unexpected transaction version.")
    require(unsigned["locktime"] == 0, "Unexpected locktime.")
    require(len(unsigned["vin"]) == 1, "Expected exactly one input.")
    require(len(unsigned["vout"]) == 2, "Expected exactly two outputs.")

    unsigned_input = unsigned["vin"][0]
    require(unsigned_input["txid"] == funding_txid, "Input TXID mismatch.")
    require(unsigned_input["vout"] == funding_vout, "Input vout mismatch.")
    require(unsigned_input["sequence"] == 4294967294, "Sequence mismatch.")
    require(unsigned_input["scriptSig"]["hex"] == "", "scriptSig is not empty.")
    require("txinwitness" not in unsigned_input, "Unexpected witness in unsigned tx.")

    expected_outputs = [
        (destination_address, payment_sat),
        (change_address, change_sat),
    ]
    for index, (address, amount_sat) in enumerate(expected_outputs):
        output = unsigned["vout"][index]
        require(output["n"] == index, f"Output {index} index mismatch.")
        require(
            output["scriptPubKey"].get("address") == address,
            f"Output {index} address mismatch.",
        )
        require(
            btc_to_sat(output["value"]) == amount_sat,
            f"Output {index} amount mismatch.",
        )
        require(
            output["scriptPubKey"].get("type") == "pubkeyhash",
            f"Output {index} is not P2PKH.",
        )

    # 3. Sign with SIGHASH_ALL.
    signed_result = rpc(
        "signrawtransactionwithwallet",
        unsigned_hex,
        [],
        "ALL",
        wallet=wallet_name,
    )
    require(isinstance(signed_result, dict), "Invalid signing result.")
    require(
        signed_result.get("complete") is True,
        "Wallet did not completely sign the transaction:\n"
        + json.dumps(signed_result, indent=2),
    )

    signed_hex = str(signed_result["hex"])
    try:
        bytes.fromhex(signed_hex)
    except ValueError as exc:
        raise BuildTransactionError(f"Invalid signed transaction hex: {exc}")

    signed = rpc("decoderawtransaction", signed_hex, False)
    require(isinstance(signed, dict), "Could not decode signed transaction.")
    require(signed["version"] == 2, "Signing changed version.")
    require(signed["locktime"] == 0, "Signing changed locktime.")
    require(len(signed["vin"]) == 1, "Signing changed input count.")
    require(len(signed["vout"]) == 2, "Signing changed output count.")

    signed_input = signed["vin"][0]
    require("txinwitness" not in signed_input, "Legacy input has witness.")
    script_sig_hex = str(signed_input["scriptSig"]["hex"])
    require(bool(script_sig_hex), "Signed transaction has empty scriptSig.")

    script_sig = bytes.fromhex(script_sig_hex)
    signature_with_type, offset = read_direct_push(script_sig, 0)
    public_key, offset = read_direct_push(script_sig, offset)
    require(offset == len(script_sig), "Trailing bytes in scriptSig.")
    require(
        len(signature_with_type) >= 9 and signature_with_type[0] == 0x30,
        "First scriptSig item is not a DER signature.",
    )
    require(
        signature_with_type[-1] == 0x01,
        "Signature does not use SIGHASH_ALL (0x01).",
    )
    require(
        len(public_key) == 33 and public_key[0] in (0x02, 0x03),
        "Second scriptSig item is not a compressed public key.",
    )
    require(signed["txid"] == signed["hash"], "TXID and WTXID differ.")

    # 4. Mempool preflight only; no broadcast.
    acceptance = rpc("testmempoolaccept", [signed_hex])
    require(
        isinstance(acceptance, list) and len(acceptance) == 1,
        "Unexpected testmempoolaccept result.",
    )
    accept = acceptance[0]
    require(
        accept.get("allowed") is True,
        "Mempool preflight rejected the transaction:\n"
        + json.dumps(accept, indent=2),
    )

    actual_fee_sat = btc_to_sat(accept["fees"]["base"])
    vsize = int(accept["vsize"])
    fee_rate_sat_vb = Decimal(actual_fee_sat) / Decimal(vsize)
    require(actual_fee_sat == expected_fee_sat, "Transaction fee mismatch.")
    require(accept["txid"] == signed["txid"], "Preflight TXID mismatch.")
    require(accept["wtxid"] == signed["hash"], "Preflight WTXID mismatch.")

    # 5. Save only after every check passed.
    updated = dict(metadata)
    updated.update({
        "experiment_unsigned_txid": unsigned["txid"],
        "experiment_txid": signed["txid"],
        "experiment_wtxid": signed["hash"],
        "experiment_version": signed["version"],
        "experiment_locktime": signed["locktime"],
        "experiment_sequence": signed_input["sequence"],
        "experiment_size_bytes": signed["size"],
        "experiment_vsize": signed["vsize"],
        "experiment_weight": signed["weight"],
        "experiment_script_sig_hex": script_sig_hex,
        "experiment_signature_size_bytes": len(signature_with_type),
        "experiment_public_key": public_key.hex(),
        "experiment_sighash_type": "ALL",
        "experiment_sighash_byte": "01",
        "experiment_fee_rate_sat_vb": float(fee_rate_sat_vb),
        "experiment_mempool_allowed": True,
        "experiment_broadcast": False,
    })

    atomic_write(UNSIGNED_PATH, unsigned_hex + "\n")
    atomic_write(SIGNED_PATH, signed_hex + "\n")
    atomic_write(METADATA_PATH, json.dumps(updated, indent=2) + "\n")

    print("=" * 72)
    print("UNSIGNED TRANSACTION")
    print("=" * 72)
    print(f"Version / locktime : {unsigned['version']} / {unsigned['locktime']}")
    print(f"Inputs / outputs   : {len(unsigned['vin'])} / {len(unsigned['vout'])}")
    print(f"Input outpoint     : {funding_txid}:{funding_vout}")
    print(f"Input sequence     : {unsigned_input['sequence']} (0xfffffffe)")
    print("scriptSig          : empty")
    print("Witness            : absent")
    print(f"Output 0 payment   : {payment_sat} sat -> {destination_address}")
    print(f"Output 1 change    : {change_sat} sat -> {change_address}")
    print(f"Saved              : {UNSIGNED_PATH.relative_to(PROJECT_ROOT)}")
    print()

    print("=" * 72)
    print("SIGNED LEGACY P2PKH TRANSACTION")
    print("=" * 72)
    print(f"TXID               : {signed['txid']}")
    print(f"WTXID              : {signed['hash']}")
    print(f"TXID == WTXID      : {signed['txid'] == signed['hash']}")
    print(f"Size / vsize       : {signed['size']} / {signed['vsize']} bytes")
    print(f"Weight             : {signed['weight']}")
    print(f"scriptSig bytes    : {len(script_sig)}")
    print(f"scriptSig hex      : {script_sig_hex}")
    print(f"scriptSig asm      : {signed_input['scriptSig']['asm']}")
    print(f"Signature push     : {len(signature_with_type)} bytes")
    print(f"Sighash byte       : 0x{signature_with_type[-1]:02x} (SIGHASH_ALL)")
    print(f"Compressed pubkey  : {public_key.hex()}")
    print("Witness            : absent")
    print(f"Fee                : {actual_fee_sat} sat")
    print(f"Fee rate           : {fee_rate_sat_vb:.3f} sat/vB")
    print(f"Saved              : {SIGNED_PATH.relative_to(PROJECT_ROOT)}")
    print()

    print("=" * 72)
    print("MEMPOOL PREFLIGHT")
    print("=" * 72)
    print(f"allowed            : {accept['allowed']}")
    print(f"txid               : {accept['txid']}")
    print(f"wtxid              : {accept['wtxid']}")
    print("broadcast           : false")
    print()
    print("All checks passed. The transaction has NOT been broadcast.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildTransactionError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
