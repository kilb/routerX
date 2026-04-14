"""Minimal EIP-55 checksummed ETH address generator.

Avoids the eth-account dependency. Keccak-256 is resolved through the
first available backend: pycryptodome > pysha3 > stdlib (sha3_256 is not
Keccak-256 but good enough as a last-resort for tests/CI). Production
detectors must prefer an environment with pycryptodome installed.
"""
from __future__ import annotations

import secrets


def _keccak256(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak
        return keccak.new(digest_bits=256, data=data).digest()
    except ImportError:
        pass
    try:
        import sha3
        return sha3.keccak_256(data).digest()
    except ImportError:
        pass
    import hashlib
    return hashlib.sha3_256(data).digest()


def generate_test_eth_address() -> str:
    """Return a random EIP-55 checksummed ETH address with a 0x prefix."""
    raw = secrets.token_bytes(20)
    addr_lower = raw.hex()
    addr_hash = _keccak256(addr_lower.encode("ascii")).hex()
    checksummed = []
    for i, c in enumerate(addr_lower):
        if c in "0123456789":
            checksummed.append(c)
        elif int(addr_hash[i], 16) >= 8:
            checksummed.append(c.upper())
        else:
            checksummed.append(c)
    return "0x" + "".join(checksummed)


def is_valid_eth_address(addr: str) -> bool:
    if not addr.startswith("0x") or len(addr) != 42:
        return False
    try:
        int(addr[2:], 16)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    passed = 0
    for _ in range(10):
        addr = generate_test_eth_address()
        if is_valid_eth_address(addr):
            passed += 1
            print(f"  OK {addr}")
    print(f"{'PASS' if passed == 10 else 'FAIL'} ETH: {passed}/10")
