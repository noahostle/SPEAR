from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

MASK16 = 0xFFFF

SBOX1 = [0x1, 0xF, 0xB, 0x2, 0x0, 0x3, 0x5, 0x8, 0x6, 0x9, 0xC, 0x7, 0xD, 0xA, 0xE, 0x4]
SBOX2 = [0x6, 0xA, 0xF, 0x4, 0xE, 0xD, 0x9, 0x2, 0x1, 0x7, 0xC, 0xB, 0x0, 0x3, 0x5, 0x8]
SBOX3 = [0xC, 0x2, 0x6, 0x1, 0x0, 0x3, 0x5, 0x8, 0x7, 0x9, 0xB, 0xE, 0xA, 0xD, 0xF, 0x4]
SBOX4 = [0xD, 0xB, 0x2, 0x7, 0x0, 0x3, 0x5, 0x8, 0x6, 0xC, 0xF, 0x1, 0xA, 0x4, 0x9, 0xE]


def rotl16(x: int, shift: int) -> int:
    shift &= 15
    return ((x << shift) | (x >> (16 - shift))) & MASK16


def rotr16(x: int, shift: int) -> int:
    shift &= 15
    return ((x >> shift) | (x << (16 - shift))) & MASK16


def do_sbox(x: int) -> int:
    a = SBOX1[(x >> 12) & 0xF]
    b = SBOX2[(x >> 8) & 0xF]
    c = SBOX3[(x >> 4) & 0xF]
    d = SBOX4[x & 0xF]
    return ((a << 12) | (b << 8) | (c << 4) | d) & MASK16


def sep_rotl16(x: int) -> int:
    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF

    a ^= c
    b ^= d
    c ^= b
    d ^= a

    x = ((a << 12) | (b << 8) | (c << 4) | d) & MASK16
    return x ^ rotl16(x, 12) ^ rotl16(x, 8)


def enc_block(pt: int, key_pair: Sequence[int], n: int) -> int:
    key0 = key_pair[0] & MASK16
    key1 = key_pair[1] & MASK16

    key2 = rotl16(key0, 6)
    key2 = (key2 | (SBOX1[(key2 >> 6) & 0xF] << 6)) & MASK16
    key2 ^= (n + 2)

    key3 = rotl16(key1, 10)
    key3 = (key3 | (SBOX1[(key3 >> 6) & 0xF] << 6)) & MASK16
    key3 ^= (n + 3)

    t = pt ^ key0
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= key1
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= key2
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= key3
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= key1 ^ key0
    t = do_sbox(t)
    t ^= key2 ^ key3
    return t & MASK16


@dataclass
class SeparState:
    s1: int
    s2: int
    s3: int
    s4: int
    s5: int
    s6: int
    s7: int
    s8: int
    lfsr: int

    def as_tuple(self) -> Tuple[int, ...]:
        return (self.s1, self.s2, self.s3, self.s4, self.s5, self.s6, self.s7, self.s8, self.lfsr)


DEFAULT_KEY = [
    0xE8B9, 0xB733, 0xDA5D, 0x96D7, 0x02DD, 0x3972, 0xE953, 0x07FD,
    0x50C5, 0x12DB, 0xF44A, 0x233E, 0x8D1E, 0x9DF5, 0xFC7D, 0x6371,
]


def init_state(key: Sequence[int], iv: Sequence[int]) -> SeparState:
    s1, s2, s3, s4, s5, s6, s7, s8 = [x & MASK16 for x in iv]
    ct = 0
    for _ in range(4):
        v12 = enc_block((s1 + s3 + s5 + s7) & MASK16, key[0:2], 1)
        v23 = enc_block((v12 + s2) & MASK16, key[2:4], 2)
        v34 = enc_block((v23 + s3) & MASK16, key[4:6], 3)
        v45 = enc_block((v34 + s4) & MASK16, key[6:8], 4)
        v56 = enc_block((v45 + s5) & MASK16, key[8:10], 5)
        v67 = enc_block((v56 + s6) & MASK16, key[10:12], 6)
        v78 = enc_block((v67 + s7) & MASK16, key[12:14], 7)
        ct = enc_block((v78 + s8) & MASK16, key[14:16], 8)

        s1 = (s1 + ct) & MASK16
        s2 = (s2 + v12) & MASK16
        s3 = (s3 + v23) & MASK16
        s4 = (s4 + v34) & MASK16
        s5 = (s5 + v45) & MASK16
        s6 = (s6 + v56) & MASK16
        s7 = (s7 + v67) & MASK16
        s8 = (s8 + v78) & MASK16

    return SeparState(s1, s2, s3, s4, s5, s6, s7, s8, ct | 0x100)


def encrypt_word(pt: int, state: SeparState, key: Sequence[int]) -> Tuple[int, SeparState]:
    v12 = enc_block((pt + state.s1) & MASK16, key[0:2], 1)
    v23 = enc_block((v12 + state.s2) & MASK16, key[2:4], 2)
    v34 = enc_block((v23 + state.s3) & MASK16, key[4:6], 3)
    v45 = enc_block((v34 + state.s4) & MASK16, key[6:8], 4)
    v56 = enc_block((v45 + state.s5) & MASK16, key[8:10], 5)
    v67 = enc_block((v56 + state.s6) & MASK16, key[10:12], 6)
    v78 = enc_block((v67 + state.s7) & MASK16, key[12:14], 7)
    ct = enc_block((v78 + state.s8) & MASK16, key[14:16], 8)

    s2 = (state.s2 + v12 + v56 + state.s6) & MASK16
    s3 = (state.s3 + v23 + v34 + state.s4 + state.s1) & MASK16
    s4 = (state.s4 + v12 + v45 + state.s8) & MASK16
    s5 = (state.s5 + v23) & MASK16
    s6 = (state.s6 + v12 + v45 + state.s7) & MASK16
    s7 = (state.s7 + v23 + v67) & MASK16
    s8 = (state.s8 + v45) & MASK16
    s1 = (state.s1 + v34 + v23 + s5 + v78) & MASK16
    lfsr = ((state.lfsr >> 1) ^ (-(state.lfsr & 1) & 0xCA44)) & MASK16
    s5 = (s5 + lfsr) & MASK16

    return ct, SeparState(s1, s2, s3, s4, s5, s6, s7, s8, lfsr)


def encrypt_message(key: Sequence[int], iv: Sequence[int], pts: Iterable[int]) -> List[int]:
    state = init_state(key, iv)
    out = []
    for pt in pts:
        ct, state = encrypt_word(pt & MASK16, state, key)
        out.append(ct)
    return out
