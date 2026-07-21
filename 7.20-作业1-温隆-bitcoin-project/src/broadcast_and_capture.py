#!/usr/bin/env python3
"""
Broadcast the prepared Bitcoin Testnet4 transaction, wait for confirmation,
capture its raw transaction and complete raw block, and update metadata.

This script is intentionally idempotent:
- If the transaction is already in the mempool or already confirmed, it continues.
- If interrupted while waiting, it can be run again safely.

Inputs:
  data/metadata.json
  data/raw_transaction.hex

Outputs:
  data/raw_transaction.hex  (verified against the node)
  data/raw_block.hex
  data/metadata.json        (broadcast and block fields updated)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
METADATA_PATH = PROJECT_ROOT / "data" / "metadata.json"
RAW_TX_PATH = PROJECT_ROOT / "data" / "raw_transaction.hex"
RAW_BLOCK_PATH = PROJECT_ROOT / "data" / "raw_block.hex"


class CaptureError(RuntimeError):
    """Raised when broadcast, confirmation, or data capture fails."""


def atomic_write(path: Path, content: str) -> None:
    """Write via a temporary file to avoid leaving truncated output."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def run_rpc(
    method: str,
    *params: Any,
    wallet: str | None = None,
    allow_failure: bool = False,
) -> tuple[Any | None, str | None]:
    """Run bitcoin-cli and return (decoded_result, error_text)."""
    command = ["bitcoin-cli", "-testnet4"]

    if wallet is not None:
        command.append(f"-rpcwallet={wallet}")

    command.append(method)

    for param in params:
        if isinstance(param, (list, dict)):
            command.append(
                json.dumps(param, separators=(",", ":"), ensure_ascii=False)
            )
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
        error_text = result.stderr.strip() or result.stdout.strip()
        if allow_failure:
            return None, error_text
        raise CaptureError(
            f"RPC {method!r} failed.\nCommand: {' '.join(command)}\n{error_text}"
        )

    output = result.stdout.strip()
    if not output:
        return None, None

    try:
        return json.loads(output), None
    except json.JSONDecodeError:
        return output, None


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CaptureError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CaptureError(f"Missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CaptureError(f"Invalid JSON in {path}: {exc}") from exc


def read_hex_file(path: Path) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise CaptureError(f"Missing file: {path}") from exc

    if not value:
        raise CaptureError(f"Hex file is empty: {path}")

    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise CaptureError(f"Invalid hexadecimal data in {path}: {exc}") from exc

    return value


def is_already_known_error(error: str) -> bool:
    """Recognize safe rerun cases after a previous successful broadcast."""
    lowered = error.lower()
    markers = (
        "txn-already-in-mempool",
        "txn-already-known",
        "transaction already in block chain",
        "already in block chain",
        "already known",
        "already have transaction",
    )
    return any(marker in lowered for marker in markers)


def wallet_transaction(
    txid: str,
    wallet_name: str,
) -> dict[str, Any] | None:
    result, error = run_rpc(
        "gettransaction",
        txid,
        False,
        False,
        wallet=wallet_name,
        allow_failure=True,
    )
    if error is not None:
        return None
    return result if isinstance(result, dict) else None


def print_wait_status(
    txid: str,
    wallet_name: str,
    started_at: float,
) -> int:
    """Print a compact progress line and return current confirmations."""
    wallet_tx = wallet_transaction(txid, wallet_name)
    confirmations = int(wallet_tx.get("confirmations", 0)) if wallet_tx else 0

    chain_info, _ = run_rpc("getblockchaininfo")
    tip_height = (
        int(chain_info.get("blocks", -1))
        if isinstance(chain_info, dict)
        else -1
    )

    mempool_entry, mempool_error = run_rpc(
        "getmempoolentry",
        txid,
        allow_failure=True,
    )
    in_mempool = mempool_error is None and isinstance(mempool_entry, dict)

    elapsed = int(time.monotonic() - started_at)
    print(
        f"[WAIT] elapsed={elapsed:4d}s  confirmations={confirmations}  "
        f"in_mempool={str(in_mempool).lower()}  tip={tip_height}",
        flush=True,
    )
    return confirmations


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Broadcast the prepared Testnet4 transaction, wait for one "
            "confirmation, and save its complete raw block."
        )
    )
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=15,
        help="Seconds between confirmation checks (default: 15).",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=10800,
        help="Maximum wait time for confirmation (default: 10800 = 3 hours).",
    )
    args = parser.parse_args()

    require(args.poll_seconds >= 5, "--poll-seconds must be at least 5.")
    require(args.timeout_seconds > 0, "--timeout-seconds must be positive.")

    metadata = load_json(METADATA_PATH)
    signed_hex = read_hex_file(RAW_TX_PATH)

    wallet_name = str(metadata["wallet_name"])
    expected_txid = str(metadata["experiment_txid"])
    expected_wtxid = str(metadata["experiment_wtxid"])

    require(expected_txid, "metadata.json has no experiment_txid.")
    require(expected_wtxid, "metadata.json has no experiment_wtxid.")
    require(
        metadata.get("experiment_mempool_allowed") is True,
        "The transaction has not passed the saved mempool preflight.",
    )

    # Confirm the local node and wallet are ready.
    chain_info, _ = run_rpc("getblockchaininfo")
    require(isinstance(chain_info, dict), "Invalid blockchain information.")
    require(chain_info.get("chain") == "testnet4", "Node is not on Testnet4.")
    require(
        chain_info.get("initialblockdownload") is False,
        "Node is still in initial block download.",
    )

    loaded_wallets, _ = run_rpc("listwallets")
    require(
        isinstance(loaded_wallets, list) and wallet_name in loaded_wallets,
        f"Wallet {wallet_name!r} is not loaded.",
    )

    # Decode once more and verify the file has the expected identity.
    decoded, _ = run_rpc("decoderawtransaction", signed_hex, False)
    require(isinstance(decoded, dict), "Could not decode raw_transaction.hex.")
    require(decoded["txid"] == expected_txid, "Signed file TXID mismatch.")
    require(decoded["hash"] == expected_wtxid, "Signed file WTXID mismatch.")

    # Check whether this is a fresh run or a safe rerun.
    known_wallet_tx = wallet_transaction(expected_txid, wallet_name)
    already_confirmed = (
        known_wallet_tx is not None
        and int(known_wallet_tx.get("confirmations", 0)) >= 1
    )

    if not already_confirmed:
        acceptance, _ = run_rpc("testmempoolaccept", [signed_hex])
        require(
            isinstance(acceptance, list) and len(acceptance) == 1,
            "Unexpected testmempoolaccept result.",
        )
        preflight = acceptance[0]

        if preflight.get("allowed") is not True:
            reject_reason = str(preflight.get("reject-reason", ""))
            require(
                "already" in reject_reason.lower(),
                "Transaction no longer passes mempool preflight:\n"
                + json.dumps(preflight, indent=2),
            )

        broadcast_result, broadcast_error = run_rpc(
            "sendrawtransaction",
            signed_hex,
            allow_failure=True,
        )

        if broadcast_error is not None:
            require(
                is_already_known_error(broadcast_error),
                "sendrawtransaction failed:\n" + broadcast_error,
            )
            print("[BROADCAST] Transaction was already known; continuing.")
        else:
            require(
                broadcast_result == expected_txid,
                f"Broadcast TXID mismatch: expected {expected_txid}, "
                f"got {broadcast_result}.",
            )
            print(f"[BROADCAST] accepted txid={broadcast_result}")
    else:
        print("[BROADCAST] Transaction is already confirmed; continuing.")

    broadcast_timestamp = datetime.now(timezone.utc).isoformat()

    # Mark broadcast immediately so interruption while waiting remains recorded.
    metadata.update(
        {
            "experiment_broadcast": True,
            "experiment_broadcast_txid": expected_txid,
            "experiment_broadcast_time_utc": broadcast_timestamp,
        }
    )
    atomic_write(
        METADATA_PATH,
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
    )

    # Wait for at least one confirmation.
    started_at = time.monotonic()
    while True:
        confirmations = print_wait_status(
            expected_txid,
            wallet_name,
            started_at,
        )
        if confirmations >= 1:
            break

        elapsed = time.monotonic() - started_at
        if elapsed >= args.timeout_seconds:
            raise CaptureError(
                "Timed out while waiting for confirmation. The transaction "
                "has already been broadcast. Re-run this script later; it is "
                "safe and will continue from the current state."
            )

        time.sleep(args.poll_seconds)

    # Read confirmed wallet details.
    wallet_tx = wallet_transaction(expected_txid, wallet_name)
    require(wallet_tx is not None, "Wallet cannot read the confirmed transaction.")

    confirmations = int(wallet_tx["confirmations"])
    block_hash = str(wallet_tx["blockhash"])
    block_height = int(wallet_tx["blockheight"])
    block_index = int(wallet_tx["blockindex"])
    block_time = int(wallet_tx["blocktime"])
    node_tx_hex = str(wallet_tx["hex"]).strip()

    require(node_tx_hex == signed_hex, "Node transaction hex differs from saved hex.")

    # Retrieve both block summary and complete serialized block.
    block_info, _ = run_rpc("getblock", block_hash, 1)
    require(isinstance(block_info, dict), "Could not obtain block information.")
    require(block_info["hash"] == block_hash, "Block hash mismatch.")
    require(block_info["height"] == block_height, "Block height mismatch.")
    require(
        expected_txid in block_info.get("tx", []),
        "Confirmed transaction is absent from the reported block.",
    )

    raw_block_hex, _ = run_rpc("getblock", block_hash, 0)
    require(
        isinstance(raw_block_hex, str) and bool(raw_block_hex),
        "Node returned an empty raw block.",
    )

    try:
        raw_block_bytes = bytes.fromhex(raw_block_hex)
    except ValueError as exc:
        raise CaptureError(f"Raw block is not valid hexadecimal: {exc}") from exc

    require(
        len(raw_block_bytes) == int(block_info["size"]),
        f"Raw block size mismatch: hex has {len(raw_block_bytes)} bytes, "
        f"RPC reports {block_info['size']} bytes.",
    )

    # Preserve verified node data only after all checks pass.
    atomic_write(RAW_TX_PATH, node_tx_hex + "\n")
    atomic_write(RAW_BLOCK_PATH, raw_block_hex + "\n")

    metadata = load_json(METADATA_PATH)
    metadata.update(
        {
            "experiment_broadcast": True,
            "experiment_confirmations_at_capture": confirmations,
            "experiment_block_hash": block_hash,
            "experiment_block_height": block_height,
            "experiment_block_index": block_index,
            "experiment_block_time": block_time,
            "experiment_block_time_utc": datetime.fromtimestamp(
                block_time, tz=timezone.utc
            ).isoformat(),
            "experiment_raw_transaction_size_bytes": len(
                bytes.fromhex(node_tx_hex)
            ),
            "experiment_raw_block_size_bytes": len(raw_block_bytes),
            "experiment_block_tx_count": int(block_info["nTx"]),
            # Retain the original generic names used by the initial skeleton.
            "block_hash": block_hash,
            "block_height": block_height,
        }
    )
    atomic_write(
        METADATA_PATH,
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
    )

    print()
    print("=" * 76)
    print("EXPERIMENT TRANSACTION CONFIRMED AND CAPTURED")
    print("=" * 76)
    print(f"Network              : testnet4")
    print(f"TXID                 : {expected_txid}")
    print(f"WTXID                : {expected_wtxid}")
    print(f"Confirmations        : {confirmations}")
    print(f"Block height         : {block_height}")
    print(f"Block hash           : {block_hash}")
    print(f"Transaction index    : {block_index}")
    print(f"Block transaction(s) : {block_info['nTx']}")
    print(f"Raw transaction      : {len(bytes.fromhex(node_tx_hex))} bytes")
    print(f"Raw block            : {len(raw_block_bytes)} bytes")
    print(f"Saved transaction    : {RAW_TX_PATH.relative_to(PROJECT_ROOT)}")
    print(f"Saved block          : {RAW_BLOCK_PATH.relative_to(PROJECT_ROOT)}")
    print("Metadata updated     : data/metadata.json")
    print()
    print("The transaction is now permanently recorded on Bitcoin Testnet4.")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(
            "\nInterrupted while waiting. The broadcast is not undone; "
            "run the script again to continue.",
            file=sys.stderr,
        )
        raise SystemExit(130)
    except CaptureError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise SystemExit(1)
