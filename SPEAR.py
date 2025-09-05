#!/usr/bin/env python3
"""
SEPAR prefix-conditioned 16-bit codebook attack using ./SEPAR.so (this is the authors implementation,
but I modified it slightly to add a wrapper for compatability with python, and exported to a shared obj for ctypes).


Usage:
- encode:   encrypt any hex string (length multiple of 4) and print the ciphertext.
- poc:      given full plaintext, encrypt it, then reconstruct it solely from the ciphertext
            using prefix-conditioned codebooks, timing each chunk and using caching.



Author: (you)
"""

import argparse
import ctypes
import hashlib
import os
import struct
import time
from typing import Dict, Optional

CHUNK_HEX_CHARS = 4  # 16 bits per chunk

# =========================
# Shared Library Wrapper
# =========================

class SeparLib:
    def __init__(self, lib_path: str = "./SEPAR.so"):
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"Shared library not found: {lib_path}")
        self._lib = ctypes.CDLL(lib_path)
        self._lib.call.argtypes = (ctypes.c_char_p,)
        self._lib.call.restype = ctypes.c_char_p

    def encrypt_hex(self, plaintext_hex: str) -> str:
        if len(plaintext_hex) == 0 or (len(plaintext_hex) % CHUNK_HEX_CHARS) != 0:
            raise ValueError("Plaintext length must be a positive multiple of 4 hex chars (16-bit chunks).")
        arg = plaintext_hex.encode("ascii")
        res_ptr = self._lib.call(arg)
        if not res_ptr:
            raise RuntimeError("lib.call returned NULL")
        out = ctypes.cast(res_ptr, ctypes.c_char_p).value
        if out is None:
            raise RuntimeError("Failed to read result from lib.call")
        ct = out.decode("ascii").strip()
        if len(ct) != len(plaintext_hex):
            raise ValueError(f"Unexpected ciphertext length: got {len(ct)} hex chars; expected {len(plaintext_hex)}.")
        return ct

# =========================
# Codebook per (position, prefix)
# =========================

def _codebook_path(cache_dir: str, pos: int, prefix_hex: str) -> str:
    h = hashlib.sha1(prefix_hex.upper().encode('ascii')).hexdigest()
    return os.path.join(cache_dir, f"pos{pos}_pref{h}.bin")

def build_prefix_codebook(lib: SeparLib, pos: int, prefix_hex: str, cache_dir: str) -> bytes:
    """
    Build/load codebook for chunk position `pos` under context 'prefix_hex' (plaintext chunks 0..pos-1).
    Table[x] = ciphertext_chunk produced by encrypt(prefix || x). Stored as 65536×uint16 (big-endian).
    """
    os.makedirs(cache_dir, exist_ok=True)
    path = _codebook_path(cache_dir, pos, prefix_hex)
    if os.path.exists(path):
        print(f"[+] Loading cached codebook: pos={pos}, prefix_len={len(prefix_hex)} -> {path}")
        return open(path, "rb").read()

    print(f"[+] Building codebook: pos={pos}, prefix_len={len(prefix_hex)} -> {path}")
    t0 = time.perf_counter()
    table = bytearray(65536 * 2)
    for x in range(65536):
        xhex = f"{x:04X}"
        pt = prefix_hex + xhex
        ct = lib.encrypt_hex(pt)
        cchunk = ct[-4:]  # last 4 hex correspond to this chunk
        c16 = int(cchunk, 16)
        struct.pack_into(">H", table, x * 2, c16)
        if (x & 0xFFF) == 0:  # every 4096
            print(f"    Progress: {x}/65536 ({x/65536.0:.1%})", end="\r", flush=True)
    elapsed = time.perf_counter() - t0
    with open(path, "wb") as f:
        f.write(table)
    print(f"[+] Codebook saved: {path}  |  time: {elapsed:.2f}s")
    return bytes(table)

def invert_with_codebook(codebook_bytes: bytes, c16: int) -> int:
    """
    Given the codebook table built for (pos, prefix), find the x such that table[x] == c16.
    Returns x (0..65535). Builds inverse index on the fly.
    """
    if len(codebook_bytes) != 65536 * 2:
        raise ValueError("Invalid codebook length.")
    inv = {}
    mv = memoryview(codebook_bytes)
    for x in range(65536):
        val = struct.unpack_from(">H", mv, x * 2)[0]
        inv[val] = x
    if c16 not in inv:
        raise KeyError("Ciphertext chunk not found in this prefix-conditioned codebook.")
    return inv[c16]

# =========================
# Helpers
# =========================

def encode_mode(lib: SeparLib, plaintext_hex: str):
    print(lib.encrypt_hex(plaintext_hex))

def poc_mode(lib: SeparLib, plaintext_hex: str, cache_dir: str):
    """
    1) Encrypt plaintext to get target ciphertext.
    2) Walk chunks i = 0..N-1, building/loading codebooks conditioned on the already recovered prefix (plaintext 0..i-1).
    3) Invert each ciphertext chunk via that codebook; verify it matches the true plaintext.
    """
    if len(plaintext_hex) == 0 or (len(plaintext_hex) % CHUNK_HEX_CHARS) != 0:
        raise SystemExit("Plaintext must be a positive multiple of 4 hex chars.")
    ct = lib.encrypt_hex(plaintext_hex)
    print(f"[+] Ciphertext: {ct}")
    N = len(plaintext_hex) // 4
    recovered = []
    for i in range(N):
        true_prefix = plaintext_hex[:i*4]  # KNOWN prefix for PoC
        cchunk_hex = ct[i*4:(i+1)*4]
        print(f"[#] Position {i}  |  prefix='{true_prefix or '∅'}'  target_ct_chunk={cchunk_hex}")
        t0 = time.perf_counter()
        codebook = build_prefix_codebook(lib, i, true_prefix, cache_dir)
        x = invert_with_codebook(codebook, int(cchunk_hex, 16))
        took = time.perf_counter() - t0
        pchunk = f"{x:04X}"
        recovered.append(pchunk)
        print(f"    -> recovered {pchunk}  |  elapsed {took:.2f}s")
    rec_plain = "".join(recovered)
    print(f"[+] Recovered plaintext: {rec_plain}")
    if rec_plain.upper() != plaintext_hex.upper():
        print("[!] WARNING: recovered does not match input (PoC failed).")
    else:
        print("[!] PoC successful: recovered matches input.")


# =========================
# CLI
# =========================

def main():
    ap = argparse.ArgumentParser(description="SEPAR prefix-conditioned codebook attack using ./SEPAR.so")
    ap.add_argument("--mode", required=True, choices=["encode", "poc", "decrypt"],
                    help="encode: encrypt any hex; poc: encrypt then recover; decrypt: recover from ciphertext only")
    ap.add_argument("--plaintext", help="Hex plaintext (multiple of 4 hex chars) for encode/poc")
    ap.add_argument("--ciphertext", help="Hex ciphertext (multiple of 4 hex chars) for decrypt")

    args = ap.parse_args()

    lib = SeparLib("./SEPAR.so")

    if args.mode == "encode":
        if not args.plaintext:
            raise SystemExit("--plaintext required for encode")
        encode_mode(lib, args.plaintext)
        return

    if args.mode == "poc":
        if not args.plaintext:
            raise SystemExit("--plaintext required for poc")
        os.makedirs("./cache", exist_ok=True)
        poc_mode(lib, args.plaintext, "./cache")
        return


if __name__ == "__main__":
    main()

