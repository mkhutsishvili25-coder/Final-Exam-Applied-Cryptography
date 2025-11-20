"""
Task 5 – Hashing & Integrity Check Utility

Deliverables:
- hash_util.py
- original.txt
- tampered.txt
- hashes.json

Run with:
    python hash_util.py
"""

import hashlib
import json
import os
from typing import Dict


def compute_hashes(data: bytes) -> Dict[str, str]:
    """Return SHA-256, SHA-1, and MD5 hashes for given bytes."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def ensure_original_file(path: str = "original.txt") -> None:
    """Create an example original.txt if it doesn't exist."""
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write("This is the original file used for the hashing and integrity check.\n")
        print(f"[INFO] Created default {path}")
    else:
        print(f"[INFO] Using existing {path}")


def create_tampered_file(original: str = "original.txt", tampered: str = "tampered.txt") -> None:
    """Create tampered.txt by copying original and adding one extra line."""
    with open(original, "rb") as f:
        original_data = f.read()

    tampered_data = original_data + b"THIS LINE WAS ADDED TO SIMULATE TAMPERING.\n"

    with open(tampered, "wb") as f:
        f.write(tampered_data)

    print(f"[INFO] Created {tampered} based on {original} with an extra line.")


def main():
    # 1. Ensure original.txt exists
    ensure_original_file("original.txt")

    # 2. Read original file and compute hashes
    with open("original.txt", "rb") as f:
        original_data = f.read()
    original_hashes = compute_hashes(original_data)

    # 3. Create tampered.txt and compute its hashes
    create_tampered_file("original.txt", "tampered.txt")
    with open("tampered.txt", "rb") as f:
        tampered_data = f.read()
    tampered_hashes = compute_hashes(tampered_data)

    # 4. Store hashes in hashes.json
    result = {
        "original_file": "original.txt",
        "tampered_file": "tampered.txt",
        "original_hashes": original_hashes,
        "tampered_hashes": tampered_hashes,
    }

    with open("hashes.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    print("\n[INFO] Hashes saved to hashes.json\n")

    # 5. Compare hashes and report integrity result
    print("Original file hashes:")
    for algo, h in original_hashes.items():
        print(f"  {algo.upper()}: {h}")

    print("\nTampered file hashes:")
    for algo, h in tampered_hashes.items():
        print(f"  {algo.upper()}: {h}")

    print("\nIntegrity check result:")

    if original_hashes["sha256"] == tampered_hashes["sha256"]:
        print("  PASS – SHA-256 hashes match (no change detected).")
    else:
        print("  FAIL – SHA-256 hashes differ! File has been tampered with.")

    # (Optional) also show SHA-1 / MD5 comparison
    for algo in ("sha1", "md5"):
        status = "MATCH" if original_hashes[algo] == tampered_hashes[algo] else "DIFFER"
        print(f"  {algo.upper()}: {status}")


if __name__ == "__main__":
    main()
