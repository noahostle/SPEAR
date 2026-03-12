#!/usr/bin/env python3

import argparse
import ctypes
import hashlib
import os
import struct
import time
from typing import List, Optional, Sequence

CHUNK_HEX_CHARS = 4  # 16 bits per chunk
KEY_WORDS = 16
IV_WORDS = 8


def _default_lib_path() -> str:
    return "SEPAR/SEPAR.dll"


def _normalize_hex_words(hex_string: str, *, expected_words: Optional[int] = None, field_name: str = "hex") -> str:
    hex_string = hex_string.strip()
    if hex_string.startswith(("0x", "0X")):
        hex_string = hex_string[2:]

    if len(hex_string) == 0 or (len(hex_string) % CHUNK_HEX_CHARS) != 0:
        raise ValueError(
            f"{field_name} length must be a positive multiple of {CHUNK_HEX_CHARS} hex chars (16-bit chunks)."
        )

    try:
        int(hex_string, 16)
    except ValueError as e:
        raise ValueError(f"{field_name} must be valid hex.") from e

    if expected_words is not None and (len(hex_string) // CHUNK_HEX_CHARS) != expected_words:
        raise ValueError(
            f"{field_name} must contain exactly {expected_words * CHUNK_HEX_CHARS} hex chars "
            f"({expected_words} x 16-bit words)."
        )

    return hex_string.upper()


def _hex_to_words(hex_string: str, *, expected_words: Optional[int] = None, field_name: str = "hex") -> List[int]:
    normalized = _normalize_hex_words(hex_string, expected_words=expected_words, field_name=field_name)
    return [int(normalized[i : i + CHUNK_HEX_CHARS], 16) for i in range(0, len(normalized), CHUNK_HEX_CHARS)]


def _words_to_hex(words: Sequence[int]) -> str:
    return "".join(f"{word:04X}" for word in words)


# =========================
# Shared Library Wrapper
# =========================

class SeparLib:
    """
    Wrapper for the high-throughput separ_encrypt_words buffer API.
    """

    def __init__(self, lib_path: Optional[str] = None, key_hex: Optional[str] = None, iv_hex: Optional[str] = None):
        if lib_path is None:
            lib_path = _default_lib_path()
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"Shared library not found: {lib_path}")

        self._lib = ctypes.CDLL(lib_path)
        self._encrypt_words = self._lib.separ_encrypt_words
        self._encrypt_words.argtypes = (
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint16),
        )
        self._encrypt_words.restype = ctypes.c_int

        self._key_words = self._make_fixed_word_buffer(key_hex, KEY_WORDS, "key") if key_hex else None
        self._iv_words = self._make_fixed_word_buffer(iv_hex, IV_WORDS, "iv") if iv_hex else None

    @staticmethod
    def _make_fixed_word_buffer(hex_string: str, expected_words: int, field_name: str):
        words = _hex_to_words(hex_string, expected_words=expected_words, field_name=field_name)
        return (ctypes.c_uint16 * expected_words)(*words)

    def encrypt_words_into(self, pt_words, ct_words, word_count: int) -> None:
        rc = self._encrypt_words(pt_words, word_count, self._key_words, self._iv_words, ct_words)
        if rc != 0:
            raise RuntimeError(f"separ_encrypt_words failed with status {rc}")

    def encrypt_words(self, plaintext_words: Sequence[int]) -> List[int]:
        word_count = len(plaintext_words)
        pt_buf = (ctypes.c_uint16 * word_count)(*plaintext_words)
        ct_buf = (ctypes.c_uint16 * word_count)()
        self.encrypt_words_into(pt_buf, ct_buf, word_count)
        return list(ct_buf)

    def encrypt_hex(self, plaintext_hex: str) -> str:
        plaintext_words = _hex_to_words(plaintext_hex, field_name="plaintext")
        ciphertext_words = self.encrypt_words(plaintext_words)
        return _words_to_hex(ciphertext_words)


# =========================
# Codebook per (position, prefix)
# =========================

def _codebook_path(cache_dir: str, pos: int, prefix_hex: str) -> str:
    h = hashlib.sha1(prefix_hex.upper().encode("ascii")).hexdigest()
    return os.path.join(cache_dir, f"pos{pos}_pref{h}.bin")


def build_prefix_codebook(lib: SeparLib, pos: int, prefix_hex: str, cache_dir: str) -> bytes:
    """
    Build/load codebook for chunk position `pos` under context 'prefix_hex' (plaintext chunks 0..pos-1).
    Table[x] = ciphertext chunk produced by encrypt(prefix || x). Stored as 65536xuint16 (big-endian).
    """
    os.makedirs(cache_dir, exist_ok=True)
    path = _codebook_path(cache_dir, pos, prefix_hex)

    if os.path.exists(path):
        print(f"[+] Loading cached codebook: pos={pos}, prefix_len={len(prefix_hex)} -> {path}")
        with open(path, "rb") as f:
            data = f.read()
        if len(data) != 65536 * 2:
            raise ValueError(f"Cached codebook has wrong size: {len(data)} bytes (expected {65536 * 2}).")
        return data

    print(f"[+] Building codebook: pos={pos}, prefix_len={len(prefix_hex)} -> {path}")
    t0 = time.perf_counter()

    prefix_words = _hex_to_words(prefix_hex, field_name="prefix") if prefix_hex else []
    word_count = len(prefix_words) + 1
    pt_buf = (ctypes.c_uint16 * word_count)()
    ct_buf = (ctypes.c_uint16 * word_count)()
    for i, word in enumerate(prefix_words):
        pt_buf[i] = word

    table = bytearray(65536 * 2)
    for x in range(65536):
        pt_buf[word_count - 1] = x
        lib.encrypt_words_into(pt_buf, ct_buf, word_count)
        struct.pack_into(">H", table, x * 2, ct_buf[word_count - 1])

        if (x & 0xFFF) == 0:  # every 4096
            print(f"    Progress: {x}/65536 ({x / 65536.0:.1%})", end="\r", flush=True)

    elapsed = time.perf_counter() - t0
    with open(path, "wb") as f:
        f.write(table)

    print(f"\n[+] Codebook saved: {path}  |  time: {elapsed:.2f}s")
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
# Helpers / Modes
# =========================

def _pad_bytes_to_16bit_chunks(b: bytes) -> bytes:
    # Need multiples of 2 bytes because the cipher works in 16-bit chunks (4 hex chars)
    if len(b) % 2 == 0:
        return b
    return b + b"\x00"


def encrypt_hex_mode(lib: SeparLib, plaintext_hex: str) -> None:
    print(lib.encrypt_hex(plaintext_hex))


def encrypt_text_mode(lib: SeparLib, plaintext: str) -> None:
    b = plaintext.encode("utf-8")
    b = _pad_bytes_to_16bit_chunks(b)

    pt_hex = b.hex().upper()
    print(f"[+] Plaintext (UTF-8) as hex (padded if needed): {pt_hex}")
    ct_hex = lib.encrypt_hex(pt_hex)
    print(f"[+] Ciphertext hex: {ct_hex}")


def crack_mode(lib: SeparLib, ciphertext_hex: str, cache_dir: str) -> None:
    """
    Recover plaintext from ciphertext only, chunk-by-chunk.

    For each position i:
      - prefix_hex is the plaintext recovered so far (chunks 0..i-1)
      - build/load the codebook for (i, prefix_hex)
      - invert ciphertext chunk i to recover plaintext chunk i
    """
    try:
        ciphertext_hex = _normalize_hex_words(ciphertext_hex, field_name="ciphertext")
    except ValueError as e:
        raise SystemExit(str(e))

    n_chunks = len(ciphertext_hex) // CHUNK_HEX_CHARS
    recovered = []

    for i in range(n_chunks):
        prefix_hex = "".join(recovered)
        cchunk_hex = ciphertext_hex[i * CHUNK_HEX_CHARS : (i + 1) * CHUNK_HEX_CHARS]
        prefix_display = prefix_hex if prefix_hex else "<empty>"

        print(f"[#] Position {i}  |  prefix='{prefix_display}'  target_ct_chunk={cchunk_hex}")
        t0 = time.perf_counter()

        codebook = build_prefix_codebook(lib, i, prefix_hex, cache_dir)
        x = invert_with_codebook(codebook, int(cchunk_hex, 16))

        took = time.perf_counter() - t0
        pchunk = f"{x:04X}"
        recovered.append(pchunk)

        print(f"    -> recovered {pchunk}  |  elapsed {took:.2f}s")

    rec_plain_hex = "".join(recovered)
    print(f"[+] Recovered plaintext (hex): {rec_plain_hex}")
    try:
        raw = bytes.fromhex(rec_plain_hex)
        raw = raw.rstrip(b"\x00")
        txt = raw.decode("utf-8", errors="replace")
        print(f"[+] Recovered plaintext (text): {txt}")
    except Exception as e:
        print(f"[!] Could not decode recovered plaintext as text: {e}")


# =========================
# CLI
# =========================

def main() -> None:
    default_lib = _default_lib_path()
    ap = argparse.ArgumentParser(description="SEPAR prefix-conditioned codebook attack using separ_encrypt_words")

    ap.add_argument(
        "--mode",
        required=True,
        choices=["encrypt-hex", "encrypt-text", "crack"],
        help="encrypt-hex: encrypt hex; encrypt-text: plaintext->hex(+pad)->encrypt; crack: recover plaintext from ciphertext",
    )

    ap.add_argument("--hex", help="Hex string (multiple of 4 hex chars) for encrypt-hex")
    ap.add_argument("--text", help="Plaintext string for encrypt-text (UTF-8; pads with 00 byte if needed)")
    ap.add_argument("--ciphertext", help="Hex ciphertext (multiple of 4 hex chars) for crack")
    ap.add_argument("--key", help="Optional key hex (exactly 64 hex chars; defaults to the library built-in key)")
    ap.add_argument("--iv", help="Optional IV hex (exactly 32 hex chars; defaults to the library built-in IV)")
    ap.add_argument("--cache", default="./cache", help="Directory to cache codebooks (default: ./cache)")
    ap.add_argument("--lib", default=default_lib, help=f"Path to SEPAR shared library (default: {default_lib})")

    args = ap.parse_args()
    lib = SeparLib(args.lib, key_hex=args.key, iv_hex=args.iv)

    if args.mode == "encrypt-hex":
        if not args.hex:
            raise SystemExit("--hex required for encrypt-hex")
        encrypt_hex_mode(lib, args.hex)
        return

    if args.mode == "encrypt-text":
        if args.text is None:
            raise SystemExit("--text required for encrypt-text")
        encrypt_text_mode(lib, args.text)
        return

    if args.mode == "crack":
        if not args.ciphertext:
            raise SystemExit("--ciphertext required for crack")
        os.makedirs(args.cache, exist_ok=True)
        crack_mode(lib, args.ciphertext, args.cache)
        return


if __name__ == "__main__":
    main()
