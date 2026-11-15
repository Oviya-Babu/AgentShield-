"""Cryptographic helpers – SHA-256 hashing, canonical JSON, simulated Ed25519."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sha256_hex(data: str) -> str:
    """Return the hex-encoded SHA-256 digest of a UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_entry_hash(prev_hash: str, event_dict: dict[str, Any]) -> str:
    """Hash-chain an audit entry: SHA-256(prev_hash + canonical_json(event))."""
    return sha256_hex(prev_hash + canonical_json(event_dict))


def sign_message(msg: str) -> str:
    """Simulated Ed25519 signature (SHA-256 under the hood)."""
    return "ed25519:" + sha256_hex(msg)


def verify_signature(msg: str, sig: str) -> bool:
    """Verify a simulated Ed25519 signature."""
    return sig == sign_message(msg)
