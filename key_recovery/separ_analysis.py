#!/usr/bin/env python3

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence


MASK16 = 0xFFFF

SBOX1 = (1, 15, 11, 2, 0, 3, 5, 8, 6, 9, 12, 7, 13, 10, 14, 4)
SBOX2 = (6, 10, 15, 4, 14, 13, 9, 2, 1, 7, 12, 11, 0, 3, 5, 8)
SBOX3 = (12, 2, 6, 1, 0, 3, 5, 8, 7, 9, 11, 14, 10, 13, 15, 4)
SBOX4 = (13, 11, 2, 7, 0, 3, 5, 8, 6, 12, 15, 1, 10, 4, 9, 14)

ISBOX1 = (4, 0, 3, 5, 15, 6, 8, 11, 7, 9, 13, 2, 10, 12, 14, 1)
ISBOX2 = (12, 8, 7, 13, 3, 14, 0, 9, 15, 6, 1, 11, 10, 5, 4, 2)
ISBOX3 = (4, 3, 1, 5, 15, 6, 2, 8, 7, 9, 12, 10, 0, 13, 11, 14)
ISBOX4 = (4, 11, 2, 5, 13, 6, 8, 3, 7, 14, 12, 1, 9, 0, 15, 10)

DEFAULT_KEY = (
    0xE8B9, 0xB733, 0xDA5D, 0x96D7, 0x02DD, 0x3972, 0xE953, 0x07FD,
    0x50C5, 0x12DB, 0xF44A, 0x233E, 0x8D1E, 0x9DF5, 0xFC7D, 0x6371,
)

DEFAULT_IV = (0, 0, 0, 0, 0, 0, 0, 0)


def rotl16(x: int, y: int) -> int:
    y &= 15
    return ((x << y) | (x >> (16 - y))) & MASK16


def rotr16(x: int, y: int) -> int:
    y &= 15
    return ((x >> y) | (x << (16 - y))) & MASK16


def do_sbox(x: int) -> int:
    a = SBOX1[(x >> 12) & 0xF]
    b = SBOX2[(x >> 8) & 0xF]
    c = SBOX3[(x >> 4) & 0xF]
    d = SBOX4[x & 0xF]
    return (a << 12) | (b << 8) | (c << 4) | d


def do_isbox(x: int) -> int:
    a = ISBOX1[(x >> 12) & 0xF]
    b = ISBOX2[(x >> 8) & 0xF]
    c = ISBOX3[(x >> 4) & 0xF]
    d = ISBOX4[x & 0xF]
    return (a << 12) | (b << 8) | (c << 4) | d


def sep_rotl16(x: int) -> int:
    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF

    a ^= c
    b ^= d
    c ^= b
    d ^= a

    x = (a << 12) | (b << 8) | (c << 4) | d
    return x ^ rotl16(x, 12) ^ rotl16(x, 8)


def sep_inrotl16(x: int) -> int:
    x ^= rotr16(x, 12) ^ rotr16(x, 8)

    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF

    d ^= a
    c ^= b
    b ^= d
    a ^= c

    return ((a << 12) | (b << 8) | (c << 4) | d) & MASK16


def derive_key2(k0: int, n: int) -> int:
    key2 = rotl16(k0, 6)
    b = SBOX1[(key2 >> 6) & 0xF]
    key2 |= b << 6
    return (key2 ^ (n + 2)) & MASK16


def derive_key3(k1: int, n: int) -> int:
    key3 = rotl16(k1, 10)
    b = SBOX1[(key3 >> 6) & 0xF]
    key3 |= b << 6
    return (key3 ^ (n + 3)) & MASK16


def enc_block(pt: int, key_pair: Sequence[int], n: int) -> int:
    k0 = key_pair[0] & MASK16
    k1 = key_pair[1] & MASK16
    k2 = derive_key2(k0, n)
    k3 = derive_key3(k1, n)

    t = pt ^ k0
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= k1
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= k2
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= k3
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= k1 ^ k0
    t = do_sbox(t)
    t ^= k2 ^ k3
    return t & MASK16


def dec_block(ct: int, key_pair: Sequence[int], n: int) -> int:
    k0 = key_pair[0] & MASK16
    k1 = key_pair[1] & MASK16
    k2 = derive_key2(k0, n)
    k3 = derive_key3(k1, n)

    t = ct ^ k3 ^ k2
    t = do_isbox(t)
    t ^= k0 ^ k1

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= k3

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= k2

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= k1

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= k0
    return t & MASK16


@dataclass
class SeparCtx:
    state_1: int
    state_2: int
    state_3: int
    state_4: int
    state_5: int
    state_6: int
    state_7: int
    state_8: int
    lfsr: int


def _u16(x: int) -> int:
    return x & MASK16


def initial_state(key: Sequence[int], iv: Sequence[int]) -> SeparCtx:
    s1, s2, s3, s4, s5, s6, s7, s8 = [x & MASK16 for x in iv]
    ct = 0
    for _ in range(4):
        v12 = enc_block(_u16(s1 + s3 + s5 + s7), key[0:2], 1)
        v23 = enc_block(_u16(v12 + s2), key[2:4], 2)
        v34 = enc_block(_u16(v23 + s3), key[4:6], 3)
        v45 = enc_block(_u16(v34 + s4), key[6:8], 4)
        v56 = enc_block(_u16(v45 + s5), key[8:10], 5)
        v67 = enc_block(_u16(v56 + s6), key[10:12], 6)
        v78 = enc_block(_u16(v67 + s7), key[12:14], 7)
        ct = enc_block(_u16(v78 + s8), key[14:16], 8)

        s1 = _u16(s1 + ct)
        s2 = _u16(s2 + v12)
        s3 = _u16(s3 + v23)
        s4 = _u16(s4 + v34)
        s5 = _u16(s5 + v45)
        s6 = _u16(s6 + v56)
        s7 = _u16(s7 + v67)
        s8 = _u16(s8 + v78)

    return SeparCtx(s1, s2, s3, s4, s5, s6, s7, s8, ct | 0x100)


def encrypt_word(pt: int, ctx: SeparCtx, key: Sequence[int]) -> int:
    v12 = enc_block(_u16(pt + ctx.state_1), key[0:2], 1)
    v23 = enc_block(_u16(v12 + ctx.state_2), key[2:4], 2)
    v34 = enc_block(_u16(v23 + ctx.state_3), key[4:6], 3)
    v45 = enc_block(_u16(v34 + ctx.state_4), key[6:8], 4)
    v56 = enc_block(_u16(v45 + ctx.state_5), key[8:10], 5)
    v67 = enc_block(_u16(v56 + ctx.state_6), key[10:12], 6)
    v78 = enc_block(_u16(v67 + ctx.state_7), key[12:14], 7)
    ct = enc_block(_u16(v78 + ctx.state_8), key[14:16], 8)

    ctx.state_2 = _u16(ctx.state_2 + v12 + v56 + ctx.state_6)
    ctx.state_3 = _u16(ctx.state_3 + v23 + v34 + ctx.state_4 + ctx.state_1)
    ctx.state_4 = _u16(ctx.state_4 + v12 + v45 + ctx.state_8)
    ctx.state_5 = _u16(ctx.state_5 + v23)
    ctx.state_6 = _u16(ctx.state_6 + v12 + v45 + ctx.state_7)
    ctx.state_7 = _u16(ctx.state_7 + v23 + v67)
    ctx.state_8 = _u16(ctx.state_8 + v45)
    ctx.state_1 = _u16(ctx.state_1 + v34 + v23 + ctx.state_5 + v78)

    ctx.lfsr = _u16((ctx.lfsr >> 1) ^ ((-(ctx.lfsr & 1)) & 0xCA44))
    ctx.state_5 = _u16(ctx.state_5 + ctx.lfsr)
    return ct


def decrypt_word(ct: int, ctx: SeparCtx, key: Sequence[int]) -> int:
    v78 = _u16(dec_block(ct, key[14:16], 8) - ctx.state_8)
    v67 = _u16(dec_block(v78, key[12:14], 7) - ctx.state_7)
    v56 = _u16(dec_block(v67, key[10:12], 6) - ctx.state_6)
    v45 = _u16(dec_block(v56, key[8:10], 5) - ctx.state_5)
    v34 = _u16(dec_block(v45, key[6:8], 4) - ctx.state_4)
    v23 = _u16(dec_block(v34, key[4:6], 3) - ctx.state_3)
    v12 = _u16(dec_block(v23, key[2:4], 2) - ctx.state_2)
    pt = _u16(dec_block(v12, key[0:2], 1) - ctx.state_1)

    ctx.state_2 = _u16(ctx.state_2 + v12 + v56 + ctx.state_6)
    ctx.state_3 = _u16(ctx.state_3 + v23 + v34 + ctx.state_4 + ctx.state_1)
    ctx.state_4 = _u16(ctx.state_4 + v12 + v45 + ctx.state_8)
    ctx.state_5 = _u16(ctx.state_5 + v23)
    ctx.state_6 = _u16(ctx.state_6 + v12 + v45 + ctx.state_7)
    ctx.state_7 = _u16(ctx.state_7 + v23 + v67)
    ctx.state_8 = _u16(ctx.state_8 + v45)
    ctx.state_1 = _u16(ctx.state_1 + v34 + v23 + ctx.state_5 + v78)

    ctx.lfsr = _u16((ctx.lfsr >> 1) ^ ((-(ctx.lfsr & 1)) & 0xCA44))
    ctx.state_5 = _u16(ctx.state_5 + ctx.lfsr)
    return pt


def encrypt_words(words: Sequence[int], key: Sequence[int] = DEFAULT_KEY, iv: Sequence[int] = DEFAULT_IV) -> List[int]:
    ctx = initial_state(key, iv)
    return [encrypt_word(word, ctx, key) for word in words]


def decrypt_words(words: Sequence[int], key: Sequence[int] = DEFAULT_KEY, iv: Sequence[int] = DEFAULT_IV) -> List[int]:
    ctx = initial_state(key, iv)
    return [decrypt_word(word, ctx, key) for word in words]


def parse_hex_words(hex_string: str) -> List[int]:
    s = hex_string.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    if not s or len(s) % 4:
        raise ValueError("hex string must be a non-empty multiple of 4 characters")
    return [int(s[i:i + 4], 16) for i in range(0, len(s), 4)]


def words_to_hex(words: Iterable[int]) -> str:
    return "".join(f"{word & MASK16:04X}" for word in words)


class DllOracle:
    def __init__(self, path: str | Path = Path("SEPAR") / "SEPAR.dll"):
        self.path = Path(path)
        self.lib = ctypes.CDLL(str(self.path))
        self.encrypt = self.lib.separ_encrypt_words
        self.encrypt.argtypes = (
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint16),
        )
        self.encrypt.restype = ctypes.c_int

    def encrypt_words(self, words: Sequence[int], key: Sequence[int], iv: Sequence[int]) -> List[int]:
        pt = (ctypes.c_uint16 * len(words))(*[x & MASK16 for x in words])
        ct = (ctypes.c_uint16 * len(words))()
        key_buf = (ctypes.c_uint16 * len(key))(*[x & MASK16 for x in key])
        iv_buf = (ctypes.c_uint16 * len(iv))(*[x & MASK16 for x in iv])
        rc = self.encrypt(pt, len(words), key_buf, iv_buf, ct)
        if rc != 0:
            raise RuntimeError(f"separ_encrypt_words failed with {rc}")
        return list(ct)


def self_test() -> None:
    sample = parse_hex_words("156F19E18FE6297519A352C45731536A")
    expected = "41E15D769296494746F638CE27FB07E9"
    actual = words_to_hex(encrypt_words(sample))
    if actual != expected:
        raise SystemExit(f"python model mismatch vs paper vector: {actual} != {expected}")
    recovered = words_to_hex(decrypt_words(parse_hex_words(actual)))
    if recovered != words_to_hex(sample):
        raise SystemExit(f"python decrypt mismatch: {recovered} != {words_to_hex(sample)}")

    oracle = DllOracle()
    dll_actual = words_to_hex(oracle.encrypt_words(sample, DEFAULT_KEY, DEFAULT_IV))
    if dll_actual != actual:
        raise SystemExit(f"dll mismatch: {dll_actual} != {actual}")


if __name__ == "__main__":
    self_test()
    print("self-test passed")
