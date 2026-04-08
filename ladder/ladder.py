#!/usr/bin/env python3

import argparse
import heapq
import random
from collections import defaultdict
from functools import lru_cache
from typing import Dict, List, Optional, Sequence, Tuple

import z3


DEFAULT_KEY = [
    0xE8B9, 0xB733, 0xDA5D, 0x96D7, 0x02DD, 0x3972, 0xE953, 0x07FD,
    0x50C5, 0x12DB, 0xF44A, 0x233E, 0x8D1E, 0x9DF5, 0xFC7D, 0x6371,
]

S1 = [1, 15, 11, 2, 0, 3, 5, 8, 6, 9, 12, 7, 13, 10, 14, 4]
S2 = [6, 10, 15, 4, 14, 13, 9, 2, 1, 7, 12, 11, 0, 3, 5, 8]
S3 = [12, 2, 6, 1, 0, 3, 5, 8, 7, 9, 11, 14, 10, 13, 15, 4]
S4 = [13, 11, 2, 7, 0, 3, 5, 8, 6, 12, 15, 1, 10, 4, 9, 14]

IS1 = [4, 0, 3, 5, 15, 6, 8, 11, 7, 9, 13, 2, 10, 12, 14, 1]
IS2 = [12, 8, 7, 13, 3, 14, 0, 9, 15, 6, 1, 11, 10, 5, 4, 2]
IS3 = [4, 3, 1, 5, 15, 6, 2, 8, 7, 9, 12, 10, 0, 13, 11, 14]
IS4 = [4, 11, 2, 5, 13, 6, 8, 3, 7, 14, 12, 1, 9, 0, 15, 10]

DEFAULT_DIFFS = [0x0001, 0x0002, 0x0004, 0x0008, 0x000F, 0x0010]
OUTER_BOOTSTRAP_ROWS = [0x00, 0x55, 0xAA, 0xFF]
PROGRESS_ENABLED = False


def set_progress_enabled(enabled: bool) -> None:
    global PROGRESS_ENABLED
    PROGRESS_ENABLED = bool(enabled)


def _progress_update(label: str, current: int, total: int, extra: str = "") -> None:
    if not PROGRESS_ENABLED:
        return
    total = max(1, int(total))
    current = min(max(0, int(current)), total)
    pct = (100.0 * current) / total
    prefix = f"[/] {label}"
    if extra:
        prefix += f" {extra}"
    print(f"{prefix} ({current}/{total} - {pct:5.1f}%)", end="\r")


def _progress_finish(label: str, done_label: Optional[str] = None) -> None:
    if not PROGRESS_ENABLED:
        return
    final_label = done_label or label
    print(f"[+] {final_label}... done", flush=True)

KNOWN_STAGE_IVS = {
    8: "4703EAC61B442157747A61DDA8FDDDD3",
    7: "4703EAC61B442157747A61DDA8FDDDD3",
    6: "E1A73BD303D52E6811E12AF93264B592",
    5: "D95A1E433F62724C1FACCB1919637131",
    4: "4703EAC61B442157747A61DDA8FDDDD3",
    3: "D95A1E433F62724C1FACCB1919637131",
    2: "D95A1E433F62724C1FACCB1919637131",
    1: "D95A1E433F62724C1FACCB1919637131",
}

RECURSIVE_WEAK_IV7_FAMILY = [
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0008, 0x0010, 0x0020,
    0x0040, 0x0080, 0x00FF, 0x1234, 0x5555, 0xAAAA, 0xDA5C, 0xFFFF,
    0x2707, 0x1EAE, 0xED65, 0x438F, 0xFC29, 0x8A5D, 0xC6E2, 0x901C,
    0x46A6, 0xD40D, 0x63C1, 0xFF32, 0x6C91, 0xC124, 0xC4F4, 0x5108,
]

RECURSIVE_WEAK_PREFIX_FAMILY = [
    0x0000, 0x0001, 0x000F, 0x0010, 0x00F0, 0x00FF, 0x0100, 0x0F00,
    0x1000, 0x1111, 0x2222, 0x4444, 0x8888, 0x0FF0, 0xF000, 0xFFFF,
]

_LANE_BUCKETS_BY_STAGE: Dict[int, Tuple[Dict[Tuple[int, int], List[int]], Dict[Tuple[int, int], List[int]]]] = {}
_LANE_SIGNATURES_BY_STAGE: Dict[int, List[Tuple[int, int, int, int]]] = {}
_INVERSE_LANE_PERMS_BY_STAGE: Dict[int, Dict[Tuple[int, int, int, int], Tuple[int, ...]]] = {}
_STAGE8_PROJECTED_REPS: Optional[Dict[Tuple[int, ...], List[Tuple[int, int]]]] = None

P_INVISIBLE_BITS = {
    1: (),
    2: (0, 1, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23),
    3: (0, 1, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23),
    4: (6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23),
    5: (0, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23),
    6: (0, 1, 2, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23),
    7: (0, 1, 2, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23),
    8: (0, 1, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23, 29),
}
P_INVISIBLE_BITS_STAGE8 = P_INVISIBLE_BITS[8]

STAGE_LOCAL_NIBBLE2_K0_BITS = (0, 1, 2, 3, 4, 5, 8, 9, 10, 11)
STAGE_LOCAL_NIBBLE2_K1_BITS = (0, 1, 8, 9, 10, 11, 12, 13, 14, 15)


def rotl16(x: int, y: int) -> int:
    y &= 15
    return ((x << y) | (x >> (16 - y))) & 0xFFFF


def rotr16(x: int, y: int) -> int:
    y &= 15
    return ((x >> y) | (x << (16 - y))) & 0xFFFF


def do_sbox(x: int) -> int:
    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF
    return (S1[a] << 12) | (S2[b] << 8) | (S3[c] << 4) | S4[d]


def do_isbox(x: int) -> int:
    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF
    return (IS1[a] << 12) | (IS2[b] << 8) | (IS3[c] << 4) | IS4[d]


def sep_rotl16(x: int) -> int:
    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF

    a ^= c
    b ^= d
    c ^= b
    d ^= a

    x = ((a << 12) | (b << 8) | (c << 4) | d) & 0xFFFF
    return (x ^ rotl16(x, 12) ^ rotl16(x, 8)) & 0xFFFF


def sep_inrotl16(x: int) -> int:
    x = (x ^ rotr16(x, 12) ^ rotr16(x, 8)) & 0xFFFF

    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF

    d ^= a
    c ^= b
    b ^= d
    a ^= c
    return ((a << 12) | (b << 8) | (c << 4) | d) & 0xFFFF


def derive_key23(k0: int, k1: int, stage_idx: int) -> Tuple[int, int]:
    key2 = rotl16(k0, 6)
    b = (key2 >> 6) & 0xF
    key2 |= S1[b] << 6
    key2 ^= (stage_idx + 2)
    key2 &= 0xFFFF

    key3 = rotl16(k1, 10)
    b = (key3 >> 6) & 0xF
    key3 |= S1[b] << 6
    key3 ^= (stage_idx + 3)
    key3 &= 0xFFFF
    return key2, key3


def enc_block(pt: int, key_pair: Tuple[int, int], stage_idx: int) -> int:
    k0, k1 = key_pair
    key2, key3 = derive_key23(k0, k1, stage_idx)

    t = pt ^ k0
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= k1
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= key2
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= key3
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= (k0 ^ k1)
    t = do_sbox(t)
    t ^= (key2 ^ key3)
    return t & 0xFFFF


def dec_block(ct: int, key_pair: Tuple[int, int], stage_idx: int) -> int:
    k0, k1 = key_pair
    key2, key3 = derive_key23(k0, k1, stage_idx)

    t = (ct ^ key2 ^ key3) & 0xFFFF
    t = do_isbox(t)
    t ^= (k0 ^ k1)
    t &= 0xFFFF

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= key3
    t &= 0xFFFF

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= key2
    t &= 0xFFFF

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= k1
    t &= 0xFFFF

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= k0
    return t & 0xFFFF


def parse_full_key_hex(text: str) -> List[int]:
    cleaned = text.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 64:
        raise ValueError("full key must contain exactly 64 hex chars")
    return [int(cleaned[i:i + 4], 16) for i in range(0, 64, 4)]


def parse_full_iv_hex(text: str) -> List[int]:
    cleaned = text.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 32:
        raise ValueError("IV must contain exactly 32 hex chars")
    return [int(cleaned[i:i + 4], 16) for i in range(0, 32, 4)]


def parse_iv_list(text: str) -> List[List[int]]:
    values = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        values.append(parse_full_iv_hex(part))
    return values


def parse_word_list(text: str) -> List[int]:
    values = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if part.startswith(("0x", "0X")):
            part = part[2:]
        values.append(int(part, 16) & 0xFFFF)
    return values


def parse_key_pair(text: str) -> Tuple[int, int]:
    parts = parse_word_list(text)
    if len(parts) != 2:
        raise ValueError("key pair must contain exactly two 16-bit words")
    return parts[0], parts[1]


def parse_stage_word_map(text: str) -> Dict[int, int]:
    mapping: Dict[int, int] = {}
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError("stage-word map entries must have the form stage=word")
        stage_text, word_text = part.split("=", 1)
        stage = int(stage_text, 10)
        if stage < 1 or stage > 8:
            raise ValueError("stage indices must be in 1..8")
        word_text = word_text.strip()
        if word_text.startswith(("0x", "0X")):
            word_text = word_text[2:]
        mapping[stage] = int(word_text, 16) & 0xFFFF
    return mapping


def words_to_hex(words: Sequence[int]) -> str:
    return "".join(f"{word & 0xFFFF:04X}" for word in words)


def key_words_to_hex(key_words: Sequence[int]) -> str:
    return "".join(f"{int(word) & 0xFFFF:04X}" for word in key_words)


def format_pair(pair: Tuple[int, int]) -> str:
    return f"({int(pair[0]) & 0xFFFF:04X},{int(pair[1]) & 0xFFFF:04X})"


def info(msg: str) -> None:
    print(f"[/] {msg}", flush=True)


def good(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def detail(msg: str) -> None:
    print(f"    {msg}", flush=True)


def iv_words_from_iv7(iv7: int) -> List[int]:
    words = [0] * 8
    words[7] = int(iv7) & 0xFFFF
    return words


def format_optional_prefix(prefix_words: Sequence[int]) -> str:
    return words_to_hex(prefix_words) if prefix_words else "epsilon"


def make_word_from_bits(index: int, bits: Sequence[int]) -> int:
    value = 0
    for offset, bit in enumerate(bits):
        if (index >> offset) & 1:
            value |= 1 << bit
    return value & 0xFFFF


@lru_cache(maxsize=None)
def build_stage_local_nib1_function_table() -> Dict[Tuple[int, ...], Tuple[int, int, int, int]]:
    table: Dict[Tuple[int, ...], Tuple[int, int, int, int]] = {}
    for a in range(16):
        for b in range(16):
            for c in range(16):
                for d in range(16):
                    out: List[int] = []
                    for x in range(16):
                        t = S2[x ^ a]
                        t = S2[t ^ b]
                        t = S2[t ^ c]
                        t = S2[t ^ d]
                        t = S2[t ^ a ^ b] ^ c ^ d
                        out.append(t)
                    table[tuple(out)] = (a, b, c, d)
    return table


@lru_cache(maxsize=None)
def build_stage_local_inverse_maps(stage_idx: int) -> Tuple[Dict[int, List[int]], Dict[int, List[int]]]:
    inv_k2: Dict[int, List[int]] = defaultdict(list)
    inv_k3: Dict[int, List[int]] = defaultdict(list)
    for low6 in range(64):
        key2, _ = derive_key23(low6, 0, stage_idx)
        inv_k2[(key2 >> 8) & 0xF].append(low6)
    for bits in range(64):
        k1 = (bits & 0x3) | (((bits >> 2) & 0xF) << 12)
        _, key3 = derive_key23(0, k1, stage_idx)
        inv_k3[(key3 >> 8) & 0xF].append(bits)
    return inv_k2, inv_k3


def stage_local_step1_candidates(codebook: Sequence[int]) -> List[Tuple[int, int, int, int, int, int]]:
    rows = [
        tuple((int(codebook[low | (hi << 8)]) >> 8) & 0xF for hi in range(16))
        for low in range(256)
    ]
    nib1_table = build_stage_local_nib1_function_table()

    candidates: List[Tuple[int, int, int, int, int, int]] = []
    for state_low in range(256):
        row0 = None
        row1 = None
        ok = True
        for low in range(256):
            carry = 1 if low + state_low >= 256 else 0
            row = rows[low]
            if carry:
                if row1 is None:
                    row1 = row
                elif row != row1:
                    ok = False
                    break
            else:
                if row0 is None:
                    row0 = row
                elif row != row0:
                    ok = False
                    break
        if not ok or row0 is None:
            continue
        if row1 is not None and tuple(row0[(i + 1) & 15] for i in range(16)) != row1:
            continue
        for state_hi_low in range(16):
            g = tuple(row0[(x - state_hi_low) & 15] for x in range(16))
            abcd = nib1_table.get(g)
            if abcd is not None:
                candidates.append((state_low, state_hi_low, *abcd))
    return candidates


def stage_local_step2_candidates(
    stage_idx: int,
    codebook: Sequence[int],
    step1: Sequence[Tuple[int, int, int, int, int, int]],
) -> List[Tuple[int, int, int, int]]:
    target_nib2 = [((int(codebook[x]) >> 4) & 0xF) for x in range(4096)]
    inv_k2, inv_k3 = build_stage_local_inverse_maps(stage_idx)
    survivors: List[Tuple[int, int, int, int]] = []

    for state_low, state_hi_low, a, b, c, d in step1:
        for low6 in inv_k2[c]:
            for bits in inv_k3[d]:
                base_k0 = low6 | (a << 8)
                base_k1 = (bits & 0x3) | (b << 8) | (((bits >> 2) & 0xF) << 12)
                for free in range(1 << 12):
                    k0 = base_k0 | ((free & 0x3) << 6) | (((free >> 2) & 0xF) << 12)
                    k1 = base_k1 | (((free >> 6) & 0x3F) << 2)
                    base_state = state_low | (state_hi_low << 8)
                    ok = True
                    for x in range(4096):
                        predicted = (enc_block((x + base_state) & 0x0FFF, (k0, k1), stage_idx) >> 4) & 0xF
                        if predicted != target_nib2[x]:
                            ok = False
                            break
                    if ok:
                        survivors.append((state_low, state_hi_low, k0, k1))
    return survivors


def recover_stage_local(stage_idx: int, codebook: Sequence[int]) -> List[Dict[str, int]]:
    step1 = stage_local_step1_candidates(codebook)
    step2 = stage_local_step2_candidates(stage_idx, codebook, step1)
    target = [int(value) & 0xFFFF for value in codebook]
    recovered: List[Dict[str, int]] = []
    for state_low, state_hi_low, k0, k1 in step2:
        for state_hi_top in range(16):
            state_word = state_low | (state_hi_low << 8) | (state_hi_top << 12)
            if all(enc_block((x + state_word) & 0xFFFF, (k0, k1), stage_idx) == target[x] for x in range(1 << 16)):
                recovered.append(
                    {
                        "stage": stage_idx,
                        "state_word": state_word & 0xFFFF,
                        "k0": k0 & 0xFFFF,
                        "k1": k1 & 0xFFFF,
                    }
                )
    recovered.sort(key=lambda item: (item["state_word"], item["k0"], item["k1"]))
    return recovered


def stage_key_pair(key_words: Sequence[int], stage_idx: int) -> Tuple[int, int]:
    base = 2 * (stage_idx - 1)
    return key_words[base], key_words[base + 1]


def separ_initial_ctx(key_words: Sequence[int], iv_words: Sequence[int]) -> Dict[str, List[int] | int]:
    state = list(iv_words)
    ct = 0
    for _ in range(4):
        v12 = enc_block((state[0] + state[2] + state[4] + state[6]) & 0xFFFF, stage_key_pair(key_words, 1), 1)
        v23 = enc_block((v12 + state[1]) & 0xFFFF, stage_key_pair(key_words, 2), 2)
        v34 = enc_block((v23 + state[2]) & 0xFFFF, stage_key_pair(key_words, 3), 3)
        v45 = enc_block((v34 + state[3]) & 0xFFFF, stage_key_pair(key_words, 4), 4)
        v56 = enc_block((v45 + state[4]) & 0xFFFF, stage_key_pair(key_words, 5), 5)
        v67 = enc_block((v56 + state[5]) & 0xFFFF, stage_key_pair(key_words, 6), 6)
        v78 = enc_block((v67 + state[6]) & 0xFFFF, stage_key_pair(key_words, 7), 7)
        ct = enc_block((v78 + state[7]) & 0xFFFF, stage_key_pair(key_words, 8), 8)

        state[0] = (state[0] + ct) & 0xFFFF
        state[1] = (state[1] + v12) & 0xFFFF
        state[2] = (state[2] + v23) & 0xFFFF
        state[3] = (state[3] + v34) & 0xFFFF
        state[4] = (state[4] + v45) & 0xFFFF
        state[5] = (state[5] + v56) & 0xFFFF
        state[6] = (state[6] + v67) & 0xFFFF
        state[7] = (state[7] + v78) & 0xFFFF

    return {"state": state, "lfsr": (ct | 0x100) & 0xFFFF}


def separ_encrypt_word(pt: int, ctx: Dict[str, List[int] | int], key_words: Sequence[int]) -> int:
    state = ctx["state"]
    assert isinstance(state, list)

    v12 = enc_block((pt + state[0]) & 0xFFFF, stage_key_pair(key_words, 1), 1)
    v23 = enc_block((v12 + state[1]) & 0xFFFF, stage_key_pair(key_words, 2), 2)
    v34 = enc_block((v23 + state[2]) & 0xFFFF, stage_key_pair(key_words, 3), 3)
    v45 = enc_block((v34 + state[3]) & 0xFFFF, stage_key_pair(key_words, 4), 4)
    v56 = enc_block((v45 + state[4]) & 0xFFFF, stage_key_pair(key_words, 5), 5)
    v67 = enc_block((v56 + state[5]) & 0xFFFF, stage_key_pair(key_words, 6), 6)
    v78 = enc_block((v67 + state[6]) & 0xFFFF, stage_key_pair(key_words, 7), 7)
    ct = enc_block((v78 + state[7]) & 0xFFFF, stage_key_pair(key_words, 8), 8)

    state[1] = (state[1] + v12 + v56 + state[5]) & 0xFFFF
    state[2] = (state[2] + v23 + v34 + state[3] + state[0]) & 0xFFFF
    state[3] = (state[3] + v12 + v45 + state[7]) & 0xFFFF
    state[4] = (state[4] + v23) & 0xFFFF
    state[5] = (state[5] + v12 + v45 + state[6]) & 0xFFFF
    state[6] = (state[6] + v23 + v67) & 0xFFFF
    state[7] = (state[7] + v45) & 0xFFFF
    state[0] = (state[0] + v34 + v23 + state[4] + v78) & 0xFFFF

    lfsr = ctx["lfsr"]
    assert isinstance(lfsr, int)
    lfsr = ((lfsr >> 1) ^ ((-(lfsr & 1)) & 0xCA44)) & 0xFFFF
    ctx["lfsr"] = lfsr
    state[4] = (state[4] + lfsr) & 0xFFFF
    return ct


def separ_encrypt_word_no_lfsr(pt: int, ctx: Dict[str, List[int] | int], key_words: Sequence[int]) -> int:
    state = ctx["state"]
    assert isinstance(state, list)

    v12 = enc_block((pt + state[0]) & 0xFFFF, stage_key_pair(key_words, 1), 1)
    v23 = enc_block((v12 + state[1]) & 0xFFFF, stage_key_pair(key_words, 2), 2)
    v34 = enc_block((v23 + state[2]) & 0xFFFF, stage_key_pair(key_words, 3), 3)
    v45 = enc_block((v34 + state[3]) & 0xFFFF, stage_key_pair(key_words, 4), 4)
    v56 = enc_block((v45 + state[4]) & 0xFFFF, stage_key_pair(key_words, 5), 5)
    v67 = enc_block((v56 + state[5]) & 0xFFFF, stage_key_pair(key_words, 6), 6)
    v78 = enc_block((v67 + state[6]) & 0xFFFF, stage_key_pair(key_words, 7), 7)
    ct = enc_block((v78 + state[7]) & 0xFFFF, stage_key_pair(key_words, 8), 8)

    state[1] = (state[1] + v12 + v56 + state[5]) & 0xFFFF
    state[2] = (state[2] + v23 + v34 + state[3] + state[0]) & 0xFFFF
    state[3] = (state[3] + v12 + v45 + state[7]) & 0xFFFF
    state[4] = (state[4] + v23) & 0xFFFF
    state[5] = (state[5] + v12 + v45 + state[6]) & 0xFFFF
    state[6] = (state[6] + v23 + v67) & 0xFFFF
    state[7] = (state[7] + v45) & 0xFFFF
    state[0] = (state[0] + v34 + v23 + state[4] + v78) & 0xFFFF

    lfsr = ctx["lfsr"]
    assert isinstance(lfsr, int)
    ctx["lfsr"] = ((lfsr >> 1) ^ ((-(lfsr & 1)) & 0xCA44)) & 0xFFFF
    return ct


def separ_decrypt_word(ct: int, ctx: Dict[str, List[int] | int], key_words: Sequence[int]) -> int:
    state = ctx["state"]
    assert isinstance(state, list)

    v78 = (dec_block(ct, stage_key_pair(key_words, 8), 8) - state[7]) & 0xFFFF
    v67 = (dec_block(v78, stage_key_pair(key_words, 7), 7) - state[6]) & 0xFFFF
    v56 = (dec_block(v67, stage_key_pair(key_words, 6), 6) - state[5]) & 0xFFFF
    v45 = (dec_block(v56, stage_key_pair(key_words, 5), 5) - state[4]) & 0xFFFF
    v34 = (dec_block(v45, stage_key_pair(key_words, 4), 4) - state[3]) & 0xFFFF
    v23 = (dec_block(v34, stage_key_pair(key_words, 3), 3) - state[2]) & 0xFFFF
    v12 = (dec_block(v23, stage_key_pair(key_words, 2), 2) - state[1]) & 0xFFFF
    pt = (dec_block(v12, stage_key_pair(key_words, 1), 1) - state[0]) & 0xFFFF

    state[1] = (state[1] + v12 + v56 + state[5]) & 0xFFFF
    state[2] = (state[2] + v23 + v34 + state[3] + state[0]) & 0xFFFF
    state[3] = (state[3] + v12 + v45 + state[7]) & 0xFFFF
    state[4] = (state[4] + v23) & 0xFFFF
    state[5] = (state[5] + v12 + v45 + state[6]) & 0xFFFF
    state[6] = (state[6] + v23 + v67) & 0xFFFF
    state[7] = (state[7] + v45) & 0xFFFF
    state[0] = (state[0] + v34 + v23 + state[4] + v78) & 0xFFFF

    lfsr = ctx["lfsr"]
    assert isinstance(lfsr, int)
    lfsr = ((lfsr >> 1) ^ ((-(lfsr & 1)) & 0xCA44)) & 0xFFFF
    ctx["lfsr"] = lfsr
    state[4] = (state[4] + lfsr) & 0xFFFF
    return pt


def core5(state_words: Sequence[int]) -> Tuple[int, int, int, int, int]:
    return (
        state_words[1] & 0xFFFF,
        state_words[3] & 0xFFFF,
        state_words[5] & 0xFFFF,
        state_words[6] & 0xFFFF,
        state_words[7] & 0xFFFF,
    )


def outer4(state_words: Sequence[int]) -> Tuple[int, int, int, int]:
    return (
        state_words[1] & 0xFFFF,
        state_words[3] & 0xFFFF,
        state_words[5] & 0xFFFF,
        state_words[7] & 0xFFFF,
    )


def suffix4(state_words: Sequence[int]) -> Tuple[int, int, int, int]:
    return (
        state_words[4] & 0xFFFF,
        state_words[5] & 0xFFFF,
        state_words[6] & 0xFFFF,
        state_words[7] & 0xFFFF,
    )


def suffix3(state_words: Sequence[int]) -> Tuple[int, int, int]:
    return (
        state_words[5] & 0xFFFF,
        state_words[6] & 0xFFFF,
        state_words[7] & 0xFFFF,
    )


def recover_round_state_from_outer4_pair(
    key_words: Sequence[int],
    pt_word: int,
    outer_t: Sequence[int],
    outer_next: Sequence[int],
) -> Dict[str, object]:
    s2, s4, s6, s8 = [word & 0xFFFF for word in outer_t]
    s2n, s4n, s6n, s8n = [word & 0xFFFF for word in outer_next]

    v45 = (s8n - s8) & 0xFFFF
    v12 = (s4n - s4 - s8n) & 0xFFFF
    v56 = (s2n - s2 - s6 - v12) & 0xFFFF
    s1 = (dec_block(v12, stage_key_pair(key_words, 1), 1) - pt_word) & 0xFFFF
    s5 = (dec_block(v56, stage_key_pair(key_words, 5), 5) - v45) & 0xFFFF
    s7 = (s6n - s6 - v12 - v45) & 0xFFFF
    v23 = enc_block((v12 + s2) & 0xFFFF, stage_key_pair(key_words, 2), 2)
    v34 = (dec_block(v45, stage_key_pair(key_words, 4), 4) - s4) & 0xFFFF
    s3 = (dec_block(v34, stage_key_pair(key_words, 3), 3) - v23) & 0xFFFF
    v67 = enc_block((v56 + s6) & 0xFFFF, stage_key_pair(key_words, 6), 6)
    v78 = enc_block((v67 + s7) & 0xFFFF, stage_key_pair(key_words, 7), 7)

    return {
        "full_state": [s1, s2, s3, s4, s5, s6, s7, s8],
        "outer_t": tuple(outer_t),
        "outer_next": tuple(outer_next),
        "pt_word": pt_word & 0xFFFF,
        "v12": v12,
        "v23": v23,
        "v34": v34,
        "v45": v45,
        "v56": v56,
        "v67": v67,
        "v78": v78,
    }


def recover_round_suffix_bridge(
    key_words: Sequence[int],
    pt_word: int,
    ct_word: int,
    suffix_t: Sequence[int],
    suffix_next3: Sequence[int],
) -> Dict[str, object]:
    s5, s6, s7, s8 = [word & 0xFFFF for word in suffix_t]
    s6n, s7n, s8n = [word & 0xFFFF for word in suffix_next3]

    v78 = (dec_block(ct_word & 0xFFFF, stage_key_pair(key_words, 8), 8) - s8) & 0xFFFF
    v67 = (dec_block(v78, stage_key_pair(key_words, 7), 7) - s7) & 0xFFFF
    v56 = (dec_block(v67, stage_key_pair(key_words, 6), 6) - s6) & 0xFFFF
    v45 = (s8n - s8) & 0xFFFF
    recovered_s5 = (dec_block(v56, stage_key_pair(key_words, 5), 5) - v45) & 0xFFFF
    v23 = (s7n - s7 - v67) & 0xFFFF
    v12 = (s6n - s6 - v45 - s7) & 0xFFFF
    s1 = (dec_block(v12, stage_key_pair(key_words, 1), 1) - (pt_word & 0xFFFF)) & 0xFFFF
    s2 = (dec_block(v23, stage_key_pair(key_words, 2), 2) - v12) & 0xFFFF
    s4_delta = (v12 + s8n) & 0xFFFF

    return {
        "suffix_t": tuple(int(word) & 0xFFFF for word in suffix_t),
        "suffix_next3": tuple(int(word) & 0xFFFF for word in suffix_next3),
        "pt_word": pt_word & 0xFFFF,
        "ct_word": ct_word & 0xFFFF,
        "s1": s1,
        "s2": s2,
        "s5": recovered_s5,
        "v12": v12,
        "v23": v23,
        "v45": v45,
        "v56": v56,
        "v67": v67,
        "v78": v78,
        "s4_delta": s4_delta,
        "s5_consistent": recovered_s5 == s5,
    }


def recover_round_state_from_suffix_bridge_and_next_s4(
    key_words: Sequence[int],
    bridge: Dict[str, object],
    next_s4: int,
) -> Dict[str, object]:
    s5, s6, s7, s8 = [int(word) & 0xFFFF for word in bridge["suffix_t"]]  # type: ignore[index]
    s4 = ((next_s4 & 0xFFFF) - int(bridge["s4_delta"])) & 0xFFFF
    v34 = (dec_block(int(bridge["v45"]), stage_key_pair(key_words, 4), 4) - s4) & 0xFFFF
    s3 = (dec_block(v34, stage_key_pair(key_words, 3), 3) - int(bridge["v23"])) & 0xFFFF
    full_state = [
        int(bridge["s1"]) & 0xFFFF,
        int(bridge["s2"]) & 0xFFFF,
        s3,
        s4,
        s5,
        s6,
        s7,
        s8,
    ]
    return {
        "bridge": bridge,
        "next_s4": next_s4 & 0xFFFF,
        "full_state": full_state,
        "s3": s3,
        "s4": s4,
        "v34": v34,
    }


def solve_suffix_bridge_family(
    bridge: Dict[str, object],
    *,
    next_s4: Optional[int] = None,
    max_models: int = 2,
) -> Dict[str, object]:
    s1 = z3.BitVec("s1", 16)
    s2 = z3.BitVec("s2", 16)
    s4 = z3.BitVec("s4", 16)
    s4n = z3.BitVec("s4n", 16)

    solver = z3.Solver()
    solver.add(s1 == z3.BitVecVal(int(bridge["s1"]) & 0xFFFF, 16))
    solver.add(s2 == z3.BitVecVal(int(bridge["s2"]) & 0xFFFF, 16))
    solver.add(
        s4n
        == s4
        + z3.BitVecVal(int(bridge["s4_delta"]) & 0xFFFF, 16)
    )
    if next_s4 is not None:
        solver.add(s4n == z3.BitVecVal(next_s4 & 0xFFFF, 16))

    models: List[Dict[str, int]] = []
    for _ in range(max(1, max_models)):
        if solver.check() != z3.sat:
            break
        model = solver.model()
        entry = {
            "s1": model.eval(s1, model_completion=True).as_long() & 0xFFFF,
            "s2": model.eval(s2, model_completion=True).as_long() & 0xFFFF,
            "s4": model.eval(s4, model_completion=True).as_long() & 0xFFFF,
            "s4_next": model.eval(s4n, model_completion=True).as_long() & 0xFFFF,
        }
        models.append(entry)
        solver.add(z3.Or(s4 != z3.BitVecVal(entry["s4"], 16), s4n != z3.BitVecVal(entry["s4_next"], 16)))

    return {
        "fixed_next_s4": None if next_s4 is None else (next_s4 & 0xFFFF),
        "models": models,
        "unique": len(models) <= 1,
    }


def recover_lfsr_from_outer4_triplet(
    key_words: Sequence[int],
    pt0: int,
    pt1: int,
    outer0: Sequence[int],
    outer1: Sequence[int],
    outer2: Sequence[int],
) -> Dict[str, object]:
    first = recover_round_state_from_outer4_pair(key_words, pt0, outer0, outer1)
    second = recover_round_state_from_outer4_pair(key_words, pt1, outer1, outer2)
    first_state = first["full_state"]
    second_state = second["full_state"]
    assert isinstance(first_state, list)
    assert isinstance(second_state, list)
    lfsr1 = (second_state[4] - first_state[4] - int(first["v23"])) & 0xFFFF
    return {
        "round0": first,
        "round1": second,
        "lfsr1": lfsr1,
    }


def recover_round_state_from_core_pair(
    key_words: Sequence[int],
    pt_word: int,
    core_t: Sequence[int],
    core_next: Sequence[int],
) -> Dict[str, object]:
    s2, s4, s6, s7, s8 = [word & 0xFFFF for word in core_t]
    s2n, s4n, s6n, s7n, s8n = [word & 0xFFFF for word in core_next]

    v45 = (s8n - s8) & 0xFFFF
    v12 = (s4n - s4 - s8n) & 0xFFFF
    v56 = (s2n - s2 - s6 - v12) & 0xFFFF
    s1 = (dec_block(v12, stage_key_pair(key_words, 1), 1) - pt_word) & 0xFFFF
    v67 = enc_block((v56 + s6) & 0xFFFF, stage_key_pair(key_words, 6), 6)
    v23 = (s7n - s7 - v67) & 0xFFFF
    s5 = (dec_block(v56, stage_key_pair(key_words, 5), 5) - v45) & 0xFFFF
    v34 = (dec_block(v45, stage_key_pair(key_words, 4), 4) - s4) & 0xFFFF
    s3 = (dec_block(v34, stage_key_pair(key_words, 3), 3) - v23) & 0xFFFF

    return {
        "full_state": [s1, s2, s3, s4, s5, s6, s7, s8],
        "core_t": tuple(core_t),
        "core_next": tuple(core_next),
        "pt_word": pt_word & 0xFFFF,
        "v12": v12,
        "v23": v23,
        "v34": v34,
        "v45": v45,
        "v56": v56,
        "v67": v67,
    }


def recover_lfsr_from_core_triplet(
    key_words: Sequence[int],
    pt0: int,
    pt1: int,
    core0: Sequence[int],
    core1: Sequence[int],
    core2: Sequence[int],
) -> Dict[str, object]:
    first = recover_round_state_from_core_pair(key_words, pt0, core0, core1)
    second = recover_round_state_from_core_pair(key_words, pt1, core1, core2)
    first_state = first["full_state"]
    second_state = second["full_state"]
    assert isinstance(first_state, list)
    assert isinstance(second_state, list)
    lfsr1 = (second_state[4] - first_state[4] - int(first["v23"])) & 0xFFFF
    return {
        "round0": first,
        "round1": second,
        "lfsr1": lfsr1,
    }


def decrypt_round_trace_from_state(state_words: Sequence[int], ct_word: int, key_words: Sequence[int]) -> Dict[str, int]:
    s1, s2, s3, s4, s5, s6, s7, s8 = [word & 0xFFFF for word in state_words]
    v78 = (dec_block(ct_word, stage_key_pair(key_words, 8), 8) - s8) & 0xFFFF
    v67 = (dec_block(v78, stage_key_pair(key_words, 7), 7) - s7) & 0xFFFF
    v56 = (dec_block(v67, stage_key_pair(key_words, 6), 6) - s6) & 0xFFFF
    v45 = (dec_block(v56, stage_key_pair(key_words, 5), 5) - s5) & 0xFFFF
    v34 = (dec_block(v45, stage_key_pair(key_words, 4), 4) - s4) & 0xFFFF
    v23 = (dec_block(v34, stage_key_pair(key_words, 3), 3) - s3) & 0xFFFF
    v12 = (dec_block(v23, stage_key_pair(key_words, 2), 2) - s2) & 0xFFFF
    pt = (dec_block(v12, stage_key_pair(key_words, 1), 1) - s1) & 0xFFFF
    return {
        "v78": v78,
        "v67": v67,
        "v56": v56,
        "v45": v45,
        "v34": v34,
        "v23": v23,
        "v12": v12,
        "pt": pt,
    }


def validate_exact_related_state_family(
    key_words: Sequence[int],
    *,
    delta: int,
    samples: int,
    seed: int,
) -> Dict[str, object]:
    rng = random.Random(seed)
    delta &= 0xFFFF
    enc_state_diff = [delta, 0, delta, 0, 0, 0, 0, 0]
    dec_state_diff = [delta, 0, delta, 0, 0, 0, 0, 0]
    encrypt_checks = 0
    decrypt_checks = 0
    encrypt_second_round_checks = 0
    decrypt_second_round_checks = 0

    for _ in range(samples):
        base_state = [rng.randrange(0x10000) for _ in range(8)]
        lfsr = rng.randrange(1, 0x10000)

        # First-word encryption trail: Δstate=(δ,0,...), Δpt=-δ -> Δct=0.
        left_ctx = {"state": list(base_state), "lfsr": lfsr}
        right_ctx = {"state": list(base_state), "lfsr": lfsr}
        right_ctx["state"][0] = (right_ctx["state"][0] + delta) & 0xFFFF
        pt = rng.randrange(0x10000)
        left_ct = separ_encrypt_word(pt, left_ctx, key_words)
        right_ct = separ_encrypt_word((pt - delta) & 0xFFFF, right_ctx, key_words)
        if left_ct != right_ct:
            raise AssertionError("exact related-state encryption family failed to keep the first ciphertext equal")
        state_delta = differential_state(left_ctx["state"], right_ctx["state"])
        if state_delta != enc_state_diff:
            raise AssertionError("exact related-state encryption family gave the wrong post-round state difference")
        encrypt_checks += 1

        # Second encryption word under the same Δpt=-δ exposes a pure stage-3 differential.
        enc_left_before = list(left_ctx["state"])
        enc_right_before = list(right_ctx["state"])
        pt2 = rng.randrange(0x10000)
        left_trace = round_trace_from_state(enc_left_before, pt2, key_words)
        right_trace = round_trace_from_state(enc_right_before, (pt2 - delta) & 0xFFFF, key_words)
        if int(left_trace["v12"]) != int(right_trace["v12"]):
            raise AssertionError("second-round encryption exposure failed at v12")
        if int(left_trace["v23"]) != int(right_trace["v23"]):
            raise AssertionError("second-round encryption exposure failed at v23")
        stage3_input_left = (int(left_trace["v23"]) + enc_left_before[2]) & 0xFFFF
        stage3_input_right = (int(right_trace["v23"]) + enc_right_before[2]) & 0xFFFF
        if ((stage3_input_right - stage3_input_left) & 0xFFFF) != delta:
            raise AssertionError("second-round encryption exposure did not produce the exact stage-3 input delta")
        expected_v34 = enc_block(stage3_input_right, stage_key_pair(key_words, 3), 3)
        if int(right_trace["v34"]) != expected_v34:
            raise AssertionError("second-round encryption exposure did not match the exact stage-3 block relation")
        encrypt_second_round_checks += 1

        # First-word decryption trail: same ciphertext, Δstate=(δ,0,...), Δpt=-δ.
        dec_left_ctx = {"state": list(base_state), "lfsr": lfsr}
        dec_right_ctx = {"state": list(base_state), "lfsr": lfsr}
        dec_right_ctx["state"][0] = (dec_right_ctx["state"][0] + delta) & 0xFFFF
        ct = rng.randrange(0x10000)
        left_pt = separ_decrypt_word(ct, dec_left_ctx, key_words)
        right_pt = separ_decrypt_word(ct, dec_right_ctx, key_words)
        if ((right_pt - left_pt) & 0xFFFF) != ((-delta) & 0xFFFF):
            raise AssertionError("exact related-state decryption family failed to produce the exact first-word plaintext delta")
        dec_delta = differential_state(dec_left_ctx["state"], dec_right_ctx["state"])
        if dec_delta != dec_state_diff:
            raise AssertionError("exact related-state decryption family gave the wrong post-round state difference")
        decrypt_checks += 1

        # Second decryption word under the same ciphertext exposes a pure stage-2 inverse differential.
        dec_left_before = list(dec_left_ctx["state"])
        dec_right_before = list(dec_right_ctx["state"])
        ct2 = rng.randrange(0x10000)
        left_dec_trace = decrypt_round_trace_from_state(dec_left_before, ct2, key_words)
        right_dec_trace = decrypt_round_trace_from_state(dec_right_before, ct2, key_words)
        for name in ("v78", "v67", "v56", "v45", "v34"):
            if int(left_dec_trace[name]) != int(right_dec_trace[name]):
                raise AssertionError(f"second-round decryption exposure failed at {name}")
        if ((int(right_dec_trace["v23"]) - int(left_dec_trace["v23"])) & 0xFFFF) != ((-delta) & 0xFFFF):
            raise AssertionError("second-round decryption exposure did not produce the exact stage-3 inverse output delta")
        stage2_input_left = int(left_dec_trace["v23"]) & 0xFFFF
        stage2_input_right = int(right_dec_trace["v23"]) & 0xFFFF
        expected_v12 = (dec_block(stage2_input_right, stage_key_pair(key_words, 2), 2) - dec_right_before[1]) & 0xFFFF
        if int(right_dec_trace["v12"]) != expected_v12:
            raise AssertionError("second-round decryption exposure did not match the exact stage-2 inverse block relation")
        decrypt_second_round_checks += 1

    return {
        "delta": delta,
        "encrypt_checks": encrypt_checks,
        "decrypt_checks": decrypt_checks,
        "encrypt_second_round_checks": encrypt_second_round_checks,
        "decrypt_second_round_checks": decrypt_second_round_checks,
        "post_round_state_delta": enc_state_diff,
    }


def next_word_encrypt_fingerprint(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    probe_words: Sequence[int],
) -> Tuple[int, ...]:
    ctx = separ_initial_ctx(key_words, iv_words)
    fingerprint = []
    for word in probe_words:
        trial = {"state": list(ctx["state"]), "lfsr": int(ctx["lfsr"])}
        fingerprint.append(separ_encrypt_word(int(word) & 0xFFFF, trial, key_words))
    return tuple(fingerprint)


def search_related_iv_pairs_by_fingerprint(
    key_words: Sequence[int],
    *,
    delta: int,
    trials: int,
    seed: int,
    probe_words: Sequence[int],
    truth_check: bool,
) -> Dict[str, object]:
    rng = random.Random(seed)
    probe_words = [int(word) & 0xFFFF for word in probe_words]
    shifted_probe_words = [((word - delta) & 0xFFFF) for word in probe_words]
    left_map: Dict[Tuple[int, ...], List[Tuple[List[int], Optional[Tuple[int, ...]], Optional[int]]]] = defaultdict(list)
    matches = []

    for trial in range(trials):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        left_fp = next_word_encrypt_fingerprint(key_words, iv_words, probe_words)
        right_fp = next_word_encrypt_fingerprint(key_words, iv_words, shifted_probe_words)
        truth_state = None
        truth_lfsr = None
        if truth_check:
            ctx = separ_initial_ctx(key_words, iv_words)
            state = ctx["state"]
            assert isinstance(state, list)
            truth_state = tuple(state)
            truth_lfsr = int(ctx["lfsr"])

        for other_iv, other_state, other_lfsr in left_map.get(right_fp, []):
            entry: Dict[str, object] = {
                "left_iv": words_to_hex(other_iv),
                "right_iv": words_to_hex(iv_words),
                "fingerprint": tuple(f"{value:04X}" for value in right_fp),
            }
            if truth_check and other_state is not None and truth_state is not None and other_lfsr is not None and truth_lfsr is not None:
                diff = [((truth_state[i] - other_state[i]) & 0xFFFF) for i in range(8)]
                entry["truth_state_delta"] = tuple(diff)
                entry["truth_lfsr_delta"] = (truth_lfsr - other_lfsr) & 0xFFFF
                entry["is_exact_s1_pair"] = (
                    diff[0] == delta
                    and all(diff[i] == 0 for i in range(1, 8))
                    and entry["truth_lfsr_delta"] == 0
                )
            matches.append(entry)

        left_map[left_fp].append((iv_words, truth_state, truth_lfsr))

    return {
        "delta": delta & 0xFFFF,
        "trials": trials,
        "probe_words": tuple(probe_words),
        "matches": matches,
    }


def differential_state(left: Sequence[int], right: Sequence[int]) -> List[int]:
    return [((int(right[i]) - int(left[i])) & 0xFFFF) for i in range(8)]


def round_trace_from_state(state_words: Sequence[int], pt_word: int, key_words: Sequence[int]) -> Dict[str, int]:
    s1, s2, s3, s4, s5, s6, s7, s8 = [word & 0xFFFF for word in state_words]
    v12 = enc_block((pt_word + s1) & 0xFFFF, stage_key_pair(key_words, 1), 1)
    v23 = enc_block((v12 + s2) & 0xFFFF, stage_key_pair(key_words, 2), 2)
    v34 = enc_block((v23 + s3) & 0xFFFF, stage_key_pair(key_words, 3), 3)
    v45 = enc_block((v34 + s4) & 0xFFFF, stage_key_pair(key_words, 4), 4)
    v56 = enc_block((v45 + s5) & 0xFFFF, stage_key_pair(key_words, 5), 5)
    v67 = enc_block((v56 + s6) & 0xFFFF, stage_key_pair(key_words, 6), 6)
    v78 = enc_block((v67 + s7) & 0xFFFF, stage_key_pair(key_words, 7), 7)
    ct = enc_block((v78 + s8) & 0xFFFF, stage_key_pair(key_words, 8), 8)
    return {
        "v12": v12,
        "v23": v23,
        "v34": v34,
        "v45": v45,
        "v56": v56,
        "v67": v67,
        "v78": v78,
        "ct": ct,
    }


def ctx_after_prefix(key_words: Sequence[int], iv_words: Sequence[int], prefix_words: Sequence[int]) -> Dict[str, List[int] | int]:
    ctx = separ_initial_ctx(key_words, iv_words)
    for word in prefix_words:
        separ_encrypt_word(word, ctx, key_words)
    return ctx


def next_word_table(ctx: Dict[str, List[int] | int], key_words: Sequence[int]) -> List[int]:
    state = ctx["state"]
    assert isinstance(state, list)
    table = [0] * 0x10000
    for x in range(0x10000):
        value = x
        for stage_idx in range(1, 9):
            value = enc_block((value + state[stage_idx - 1]) & 0xFFFF, stage_key_pair(key_words, stage_idx), stage_idx)
        table[x] = value
    return table


def next_word_decrypt_table(ctx: Dict[str, List[int] | int], key_words: Sequence[int]) -> List[int]:
    table = [0] * 0x10000
    for x in range(0x10000):
        trial = {"state": list(ctx["state"]), "lfsr": int(ctx["lfsr"])}
        table[x] = separ_decrypt_word(x & 0xFFFF, trial, key_words)
    return table


def diff_positions(sample_x: Sequence[int], diffs: Sequence[int]) -> List[int]:
    positions = set()
    for x in sample_x:
        positions.add(int(x) & 0xFFFF)
        for diff in diffs:
            positions.add((int(x) + int(diff)) & 0xFFFF)
    return sorted(positions)


def next_word_output(ctx: Dict[str, List[int] | int], key_words: Sequence[int], word: int, *, decrypt: bool = False) -> int:
    trial = {"state": list(ctx["state"]), "lfsr": int(ctx["lfsr"])}
    if decrypt:
        return separ_decrypt_word(word & 0xFFFF, trial, key_words)
    return separ_encrypt_word(word & 0xFFFF, trial, key_words)


def chosen_iv_row_score(
    ctx: Dict[str, List[int] | int],
    key_words: Sequence[int],
    hi_values: Sequence[int],
    *,
    decrypt: bool = False,
) -> float:
    total = 0.0
    for hi in hi_values:
        vals = set()
        base = (int(hi) & 0xFF) << 8
        for lo in range(256):
            out = next_word_output(ctx, key_words, base | lo, decrypt=decrypt)
            vals.add((out >> 8) & 0xFF)
        total += float(len(vals))
    return total / float(len(hi_values))


def raw_public_nibble_metrics_from_ctx(
    ctx: Dict[str, List[int] | int],
    key_words: Sequence[int],
    diffs: Sequence[int],
    sample_x: Sequence[int],
    *,
    decrypt: bool = False,
) -> Tuple[int, int, int]:
    positions = diff_positions(sample_x, diffs)
    observed = {
        pos: nibble2(next_word_output(ctx, key_words, pos, decrypt=decrypt))
        for pos in positions
    }
    xor_score = 0
    add_score = 0
    support_score = 0
    for diff in diffs:
        xor_counts: Dict[int, int] = {}
        add_counts: Dict[int, int] = {}
        for x in sample_x:
            left_value = observed[int(x) & 0xFFFF]
            right_value = observed[(int(x) + int(diff)) & 0xFFFF]
            xor_delta = left_value ^ right_value
            add_delta = (right_value - left_value) & 0xF
            xor_counts[xor_delta] = xor_counts.get(xor_delta, 0) + 1
            add_counts[add_delta] = add_counts.get(add_delta, 0) + 1
        xor_score += max(xor_counts.values())
        add_score += max(add_counts.values())
        support_score += len(xor_counts) + len(add_counts)
    return xor_score, add_score, support_score


def raw_public_nibble_metrics_from_table(
    table: Sequence[int],
    diffs: Sequence[int],
    sample_x: Sequence[int],
) -> Tuple[int, int, int]:
    positions = diff_positions(sample_x, diffs)
    observed = {pos: nibble2(int(table[pos]) & 0xFFFF) for pos in positions}
    xor_score = 0
    add_score = 0
    support_score = 0
    for diff in diffs:
        xor_counts: Dict[int, int] = {}
        add_counts: Dict[int, int] = {}
        for x in sample_x:
            left_value = observed[int(x) & 0xFFFF]
            right_value = observed[(int(x) + int(diff)) & 0xFFFF]
            xor_delta = left_value ^ right_value
            add_delta = (right_value - left_value) & 0xF
            xor_counts[xor_delta] = xor_counts.get(xor_delta, 0) + 1
            add_counts[add_delta] = add_counts.get(add_delta, 0) + 1
        xor_score += max(xor_counts.values())
        add_score += max(add_counts.values())
        support_score += len(xor_counts) + len(add_counts)
    return xor_score, add_score, support_score


def sampled_diff_score_from_values(values: Dict[int, int], diffs: Sequence[int], sample_x: Sequence[int]) -> int:
    total = 0
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in sample_x:
            out_diff = (int(values[(int(x) + int(diff)) & 0xFFFF]) - int(values[int(x) & 0xFFFF])) & 0xFFFF
            counts[out_diff] = counts.get(out_diff, 0) + 1
        total += max(counts.values())
    return total


def sampled_projected_add_diff_score_from_values(
    values: Dict[int, int],
    diffs: Sequence[int],
    sample_x: Sequence[int],
    *,
    shift: int,
    mask: int,
) -> int:
    total = 0
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in sample_x:
            out_diff = (int(values[(int(x) + int(diff)) & 0xFFFF]) - int(values[int(x) & 0xFFFF])) & 0xFFFF
            projected = (out_diff >> shift) & mask
            counts[projected] = counts.get(projected, 0) + 1
        total += max(counts.values())
    return total


def prefilter_tuple_from_values(
    values: Dict[int, int],
    diffs: Sequence[int],
    prefilter_diffs: Sequence[int],
    sample_x: Sequence[int],
) -> Tuple[int, int, int]:
    upper_score = sampled_projected_add_diff_score_from_values(
        values,
        prefilter_diffs,
        sample_x,
        shift=8,
        mask=0xFF,
    )
    top_nibble_score = sampled_projected_add_diff_score_from_values(
        values,
        prefilter_diffs,
        sample_x,
        shift=12,
        mask=0xF,
    )
    word_score = sampled_diff_score_from_values(values, diffs, sample_x)
    return upper_score, top_nibble_score, word_score


def nibble_prefilter_scores(
    table: Sequence[int],
    stage_idx: int,
    diffs: Sequence[int],
    sample_x: Sequence[int],
) -> List[Tuple[Tuple[int, int, int], Tuple[int, int, int, int]]]:
    positions = diff_positions(sample_x, diffs)
    observed = {pos: nibble2(int(table[pos]) & 0xFFFF) for pos in positions}
    inverse_perms = inverse_lane_perms_for_stage(stage_idx)
    ranked = []
    for signature in lane_signatures_for_stage(stage_idx):
        inverse_lane = inverse_perms[signature]
        xor_score = 0
        add_score = 0
        support_score = 0
        for diff in diffs:
            xor_counts: Dict[int, int] = {}
            add_counts: Dict[int, int] = {}
            for x in sample_x:
                left_value = inverse_lane[observed[int(x) & 0xFFFF]]
                right_value = inverse_lane[observed[(int(x) + int(diff)) & 0xFFFF]]
                xor_delta = left_value ^ right_value
                add_delta = (right_value - left_value) & 0xF
                xor_counts[xor_delta] = xor_counts.get(xor_delta, 0) + 1
                add_counts[add_delta] = add_counts.get(add_delta, 0) + 1
            xor_score += max(xor_counts.values())
            add_score += max(add_counts.values())
            support_score += len(xor_counts) + len(add_counts)
        ranked.append(((xor_score, add_score, support_score), signature))
    ranked.sort(key=lambda item: (item[0][0], item[0][1], -item[0][2], item[1]), reverse=True)
    return ranked


def pair_metric_summary(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    iv_delta: Sequence[int],
    delta_word: int,
    probe_words: Sequence[int],
) -> Dict[str, object]:
    left_ctx = separ_initial_ctx(key_words, iv_words)
    right_iv = [((int(iv_words[i]) + int(iv_delta[i])) & 0xFFFF) for i in range(8)]
    right_ctx = separ_initial_ctx(key_words, right_iv)

    enc_diffs = []
    enc_hits = 0
    for word in probe_words:
        left_out = next_word_output(left_ctx, key_words, int(word) & 0xFFFF, decrypt=False)
        right_out = next_word_output(right_ctx, key_words, (int(word) - delta_word) & 0xFFFF, decrypt=False)
        diff = (right_out - left_out) & 0xFFFF
        enc_diffs.append(diff)
        if diff == 0:
            enc_hits += 1

    dec_diffs = []
    dec_hits = 0
    target_dec = (-delta_word) & 0xFFFF
    for word in probe_words:
        left_out = next_word_output(left_ctx, key_words, int(word) & 0xFFFF, decrypt=True)
        right_out = next_word_output(right_ctx, key_words, int(word) & 0xFFFF, decrypt=True)
        diff = (right_out - left_out) & 0xFFFF
        dec_diffs.append(diff)
        if diff == target_dec:
            dec_hits += 1

    enc_counts: Dict[int, int] = {}
    for diff in enc_diffs:
        enc_counts[diff] = enc_counts.get(diff, 0) + 1
    best_enc_diff, best_enc_count = max(enc_counts.items(), key=lambda item: (item[1], -item[0]))

    dec_counts: Dict[int, int] = {}
    for diff in dec_diffs:
        dec_counts[diff] = dec_counts.get(diff, 0) + 1
    best_dec_diff, best_dec_count = max(dec_counts.items(), key=lambda item: (item[1], -item[0]))

    return {
        "right_iv": list(right_iv),
        "enc_hits": enc_hits,
        "enc_best_diff": best_enc_diff,
        "enc_best_count": best_enc_count,
        "enc_support": len(enc_counts),
        "enc_diffs": tuple(enc_diffs),
        "dec_hits": dec_hits,
        "dec_best_diff": best_dec_diff,
        "dec_best_count": best_dec_count,
        "dec_support": len(dec_counts),
        "dec_diffs": tuple(dec_diffs),
        "truth_state_delta": tuple(
            ((int(right_ctx["state"][i]) - int(left_ctx["state"][i])) & 0xFFFF)  # type: ignore[index]
            for i in range(8)
        ),
        "truth_lfsr_delta": (int(right_ctx["lfsr"]) - int(left_ctx["lfsr"])) & 0xFFFF,
        "is_exact_s1_pair": (
            ((int(right_ctx["state"][0]) - int(left_ctx["state"][0])) & 0xFFFF) == (delta_word & 0xFFFF)  # type: ignore[index]
            and all((((int(right_ctx["state"][i]) - int(left_ctx["state"][i])) & 0xFFFF) == 0) for i in range(1, 8))  # type: ignore[index]
            and (((int(right_ctx["lfsr"]) - int(left_ctx["lfsr"])) & 0xFFFF) == 0)
        ),
    }


def default_pair_patterns(delta_word: int) -> Dict[str, List[int]]:
    delta_word &= 0xFFFF
    return {
        "iv1+delta": [delta_word, 0, 0, 0, 0, 0, 0, 0],
        "iv1+delta_iv3-delta": [delta_word, 0, (-delta_word) & 0xFFFF, 0, 0, 0, 0, 0],
        "iv1+delta_iv5-delta": [delta_word, 0, 0, 0, (-delta_word) & 0xFFFF, 0, 0, 0],
        "iv1+delta_iv7-delta": [delta_word, 0, 0, 0, 0, 0, (-delta_word) & 0xFFFF, 0],
    }


def parse_hi_bytes(text: str) -> List[int]:
    values = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        values.append(int(part, 16) & 0xFF)
    return values or [0]


def parse_pair_pattern_names(text: str, delta_word: int) -> Dict[str, List[int]]:
    available = default_pair_patterns(delta_word)
    if not text.strip():
        return available
    chosen: Dict[str, List[int]] = {}
    for part in text.split(","):
        name = part.strip()
        if not name:
            continue
        if name not in available:
            raise ValueError(f"unknown pair pattern {name!r}")
        chosen[name] = available[name]
    return chosen


def evaluate_public_iv_candidate(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    *,
    hi_values: Sequence[int],
    diffs: Sequence[int],
    sample_x: Sequence[int],
    delta_word: int,
    pair_probe_words: Sequence[int],
    pair_patterns: Dict[str, List[int]],
    truth_eval: bool,
) -> Dict[str, object]:
    ctx = separ_initial_ctx(key_words, iv_words)
    row_enc = chosen_iv_row_score(ctx, key_words, hi_values, decrypt=False)
    row_dec = chosen_iv_row_score(ctx, key_words, hi_values, decrypt=True)
    raw_enc = raw_public_nibble_metrics_from_ctx(ctx, key_words, diffs, sample_x, decrypt=False)
    raw_dec = raw_public_nibble_metrics_from_ctx(ctx, key_words, diffs, sample_x, decrypt=True)

    pair_results = {}
    for name, pattern in pair_patterns.items():
        entry = pair_metric_summary(key_words, iv_words, pattern, delta_word, pair_probe_words)
        if not truth_eval:
            entry.pop("truth_state_delta", None)
            entry.pop("truth_lfsr_delta", None)
            entry.pop("is_exact_s1_pair", None)
        pair_results[name] = entry

    return {
        "iv": list(iv_words),
        "row_enc": row_enc,
        "row_dec": row_dec,
        "raw_enc": raw_enc,
        "raw_dec": raw_dec,
        "pair_results": pair_results,
    }


def public_iv_sort_key_pair(result: Dict[str, object]) -> Tuple[object, ...]:
    pair_results = result["pair_results"]
    assert isinstance(pair_results, dict)
    best_pair = max(
        pair_results.values(),
        key=lambda item: (
            int(item["enc_hits"]),
            int(item["enc_best_count"]),
            -int(item["enc_support"]),
            int(item["dec_hits"]),
            int(item["dec_best_count"]),
            -int(item["dec_support"]),
        ),
    )
    raw_enc = result["raw_enc"]
    assert isinstance(raw_enc, tuple)
    return (
        int(best_pair["enc_hits"]),
        int(best_pair["enc_best_count"]),
        -int(best_pair["enc_support"]),
        int(best_pair["dec_hits"]),
        int(best_pair["dec_best_count"]),
        -int(best_pair["dec_support"]),
        -int(raw_enc[1]),
        -int(raw_enc[0]),
        int(raw_enc[2]),
        -float(result["row_enc"]),
        -float(result["row_dec"]),
    )


def public_iv_sort_key_chosen(result: Dict[str, object]) -> Tuple[object, ...]:
    raw_enc = result["raw_enc"]
    raw_dec = result["raw_dec"]
    assert isinstance(raw_enc, tuple)
    assert isinstance(raw_dec, tuple)
    return (
        -float(result["row_enc"]),
        -float(result["row_dec"]),
        -int(raw_enc[1]),
        -int(raw_enc[0]),
        int(raw_enc[2]),
        -int(raw_dec[1]),
        -int(raw_dec[0]),
        int(raw_dec[2]),
    )


def search_public_iv_candidates(
    key_words: Sequence[int],
    *,
    trials: int,
    seed: int,
    hi_values: Sequence[int],
    diffs: Sequence[int],
    sample_x: Sequence[int],
    delta_word: int,
    pair_probe_words: Sequence[int],
    pair_patterns: Dict[str, List[int]],
    truth_eval: bool,
) -> List[Dict[str, object]]:
    rng = random.Random(seed)
    results = []
    for trial in range(1, trials + 1):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        result = evaluate_public_iv_candidate(
            key_words,
            iv_words,
            hi_values=hi_values,
            diffs=diffs,
            sample_x=sample_x,
            delta_word=delta_word,
            pair_probe_words=pair_probe_words,
            pair_patterns=pair_patterns,
            truth_eval=truth_eval,
        )
        results.append(result)
    return results


def local_iv_sort_key(result: Dict[str, object], objective: str) -> Tuple[object, ...]:
    raw_enc = result["raw_enc"]
    raw_dec = result["raw_dec"]
    assert isinstance(raw_enc, tuple)
    assert isinstance(raw_dec, tuple)
    if objective == "enc":
        return (
            float(result["row_enc"]),
            float(result["row_dec"]),
            -int(raw_enc[1]),
            -int(raw_enc[0]),
            int(raw_enc[2]),
        )
    if objective == "dec":
        return (
            float(result["row_dec"]),
            float(result["row_enc"]),
            -int(raw_dec[1]),
            -int(raw_dec[0]),
            int(raw_dec[2]),
        )
    if objective == "pair":
        pair_results = result["pair_results"]
        assert isinstance(pair_results, dict)
        best_pair = max(
            pair_results.values(),
            key=lambda item: (
                int(item["enc_hits"]),
                int(item["enc_best_count"]),
                -int(item["enc_support"]),
                int(item["dec_hits"]),
                int(item["dec_best_count"]),
                -int(item["dec_support"]),
            ),
        )
        return (
            -int(best_pair["enc_hits"]),
            -int(best_pair["enc_best_count"]),
            int(best_pair["enc_support"]),
            -int(best_pair["dec_hits"]),
            -int(best_pair["dec_best_count"]),
            int(best_pair["dec_support"]),
            float(result["row_enc"]),
            float(result["row_dec"]),
        )
    return (
        float(result["row_enc"]),
        float(result["row_dec"]),
        -int(raw_enc[1]),
        -int(raw_enc[0]),
        int(raw_enc[2]),
        -int(raw_dec[1]),
        -int(raw_dec[0]),
        int(raw_dec[2]),
    )


def mutate_iv_words(iv_words: Sequence[int], rng: random.Random) -> List[int]:
    mutated = [int(word) & 0xFFFF for word in iv_words]
    idx = rng.randrange(8)
    mode = rng.randrange(6)
    if mode == 0:
        mutated[idx] = rng.randrange(0x10000)
    elif mode == 1:
        mutated[idx] ^= 1 << rng.randrange(16)
    elif mode == 2:
        mutated[idx] = (mutated[idx] + rng.randrange(1, 0x100)) & 0xFFFF
    elif mode == 3:
        mutated[idx] = (mutated[idx] - rng.randrange(1, 0x100)) & 0xFFFF
    elif mode == 4:
        mutated[idx] = (mutated[idx] & 0xFF00) | rng.randrange(0x100)
    else:
        mutated[idx] = (mutated[idx] & 0x00FF) | (rng.randrange(0x100) << 8)
    return mutated


def local_search_public_iv_candidates(
    key_words: Sequence[int],
    *,
    starts: Sequence[Sequence[int]],
    rounds: int,
    beam: int,
    children: int,
    seed: int,
    objective: str,
    hi_values: Sequence[int],
    diffs: Sequence[int],
    sample_x: Sequence[int],
    delta_word: int,
    pair_probe_words: Sequence[int],
    pair_patterns: Dict[str, List[int]],
    truth_eval: bool,
) -> List[Dict[str, object]]:
    rng = random.Random(seed)
    pool: List[Dict[str, object]] = []
    seen = set()

    def add_candidate(iv_words: Sequence[int]) -> None:
        key = tuple(int(word) & 0xFFFF for word in iv_words)
        if key in seen:
            return
        seen.add(key)
        pool.append(
            evaluate_public_iv_candidate(
                key_words,
                list(key),
                hi_values=hi_values,
                diffs=diffs,
                sample_x=sample_x,
                delta_word=delta_word,
                pair_probe_words=pair_probe_words,
                pair_patterns=pair_patterns,
                truth_eval=truth_eval,
            )
        )

    for iv_words in starts:
        add_candidate(iv_words)

    for _ in range(max(1, rounds)):
        ranked = sorted(pool, key=lambda item: local_iv_sort_key(item, objective))
        base_items = ranked[: max(1, beam)]
        for item in base_items:
            iv_words = item["iv"]
            assert isinstance(iv_words, list)
            for _ in range(max(1, children)):
                add_candidate(mutate_iv_words(iv_words, rng))
        pool = sorted(pool, key=lambda item: local_iv_sort_key(item, objective))[: max(1, beam * 3)]

    return sorted(pool, key=lambda item: local_iv_sort_key(item, objective))


def sampled_decoded_table_score(
    table: Sequence[int],
    pair: Tuple[int, int],
    stage_idx: int,
    diffs: Sequence[int],
    sample_x: Sequence[int],
) -> Tuple[int, List[Tuple[int, int, int, int]]]:
    total = 0
    per_diff = []
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in sample_x:
            left = dec_block(int(table[(int(x) + int(diff)) & 0xFFFF]) & 0xFFFF, pair, stage_idx)
            right = dec_block(int(table[int(x) & 0xFFFF]) & 0xFFFF, pair, stage_idx)
            out_diff = (left - right) & 0xFFFF
            counts[out_diff] = counts.get(out_diff, 0) + 1
        best_out, best_count = max(counts.items(), key=lambda item: (item[1], -item[0]))
        total += best_count
        per_diff.append((diff & 0xFFFF, best_out & 0xFFFF, best_count, len(counts)))
    return total, per_diff


def exact_decoded_table_score(
    table: Sequence[int],
    pair: Tuple[int, int],
    stage_idx: int,
    diffs: Sequence[int],
) -> Tuple[int, List[Tuple[int, int, int, int]]]:
    total = 0
    per_diff = []
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in range(0x10000):
            left = dec_block(int(table[(x + diff) & 0xFFFF]) & 0xFFFF, pair, stage_idx)
            right = dec_block(int(table[x]) & 0xFFFF, pair, stage_idx)
            out_diff = (left - right) & 0xFFFF
            counts[out_diff] = counts.get(out_diff, 0) + 1
        best_out, best_count = max(counts.items(), key=lambda item: (item[1], -item[0]))
        total += best_count
        per_diff.append((diff & 0xFFFF, best_out & 0xFFFF, best_count, len(counts)))
    return total, per_diff


def sampled_outer_pair_score(
    table: Sequence[int],
    pair: Tuple[int, int],
    diffs: Sequence[int],
    prefilter_diffs: Sequence[int],
    sample_x: Sequence[int],
) -> Tuple[int, int, int]:
    positions = diff_positions(sample_x, sorted(set(diffs) | set(prefilter_diffs)))
    values = {
        pos: dec_block(int(table[pos]) & 0xFFFF, pair, 8)
        for pos in positions
    }
    return prefilter_tuple_from_values(values, diffs, prefilter_diffs, sample_x)


def signature_pair_prefilter_scores(
    table: Sequence[int],
    stage_idx: int,
    diffs: Sequence[int],
    prefilter_diffs: Sequence[int],
    sample_x: Sequence[int],
) -> List[Tuple[Tuple[int, int, int], Tuple[int, int, int, int]]]:
    nibble_scores = {
        signature: score
        for score, signature in nibble_prefilter_scores(table, stage_idx, diffs, sample_x)
    }
    ranked = []
    for signature in lane_signatures_for_stage(stage_idx):
        pair = canonical_pair_for_signature(signature, stage_idx)
        pair_score = sampled_outer_pair_score(table, pair, diffs, prefilter_diffs, sample_x)
        nibble_score = nibble_scores[signature]
        ranked.append((pair_score, nibble_score, signature))
    ranked.sort(key=lambda item: (item[0], item[1], item[2]), reverse=True)
    return [(pair_score, signature) for pair_score, _, signature in ranked]


def outer_bootstrap_iv_summary(
    ctx: Dict[str, List[int] | int],
    table: Sequence[int],
    key_words: Sequence[int],
    hi_values: Sequence[int],
    diffs: Sequence[int],
    sample_x: Sequence[int],
    *,
    truth_eval: bool,
) -> Dict[str, object]:
    row_enc = chosen_iv_row_score(ctx, key_words, hi_values, decrypt=False)
    row_dec = chosen_iv_row_score(ctx, key_words, hi_values, decrypt=True)
    raw_xor, raw_add, raw_support = raw_public_nibble_metrics_from_table(table, diffs, sample_x)
    nibble_scores = nibble_prefilter_scores(table, 8, diffs, sample_x)
    best_nibble_score = nibble_scores[0][0]
    best_nibble_tie_count = sum(1 for score, _ in nibble_scores if score == best_nibble_score)
    near_best_nibble_count = sum(
        1
        for score, _ in nibble_scores
        if score[0] >= best_nibble_score[0] - 1 and score[1] >= best_nibble_score[1] - 1
    )
    summary: Dict[str, object] = {
        "row_enc": row_enc,
        "row_dec": row_dec,
        "raw_nibble_xor": raw_xor,
        "raw_nibble_add": raw_add,
        "raw_nibble_support": raw_support,
        "best_nibble_score": best_nibble_score,
        "best_nibble_tie_count": best_nibble_tie_count,
        "near_best_nibble_count": near_best_nibble_count,
    }
    if truth_eval:
        true_pair = stage_key_pair(key_words, 8)
        true_signature = lane_pair_signature(true_pair, 8)
        true_score = next(score for score, signature in nibble_scores if signature == true_signature)
        true_rank = 1 + sum(1 for score, _ in nibble_scores if score > true_score)
        summary.update(
            {
                "true_signature": true_signature,
                "true_nibble_score": true_score,
                "true_nibble_rank": true_rank,
            }
        )
    return summary


def outer_bootstrap_sort_key(item: Dict[str, object]) -> Tuple[object, ...]:
    summary = item["summary"]
    assert isinstance(summary, dict)
    return (
        float(summary["row_enc"]),
        float(summary["row_dec"]),
        int(summary["best_nibble_tie_count"]),
        int(summary["near_best_nibble_count"]),
        -int(summary["raw_nibble_add"]),
        -int(summary["raw_nibble_xor"]),
        int(summary["raw_nibble_support"]),
    )


def search_outer_bootstrap_contexts(
    key_words: Sequence[int],
    prefix_words: Sequence[int],
    *,
    trials: int,
    seed: int,
    hi_values: Sequence[int],
    diffs: Sequence[int],
    sample_x: Sequence[int],
    truth_eval: bool,
) -> List[Dict[str, object]]:
    rng = random.Random(seed)
    results = []
    for trial in range(1, trials + 1):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        ctx = ctx_after_prefix(key_words, iv_words, prefix_words)
        table = next_word_table(ctx, key_words)
        state = ctx["state"]
        assert isinstance(state, list)
        summary = outer_bootstrap_iv_summary(
            ctx,
            table,
            key_words,
            hi_values,
            diffs,
            sample_x,
            truth_eval=truth_eval,
        )
        results.append(
            {
                "iv": list(iv_words),
                "table": table,
                "state": list(state),
                "summary": summary,
            }
        )
    return results


def outer_bootstrap_from_iv(
    table: Sequence[int],
    key_words: Sequence[int],
    diffs: Sequence[int],
    prefilter_diffs: Sequence[int],
    sample_x: Sequence[int],
    signature_beam: int,
    pair_class_limit: Optional[int],
    pair_class_seed: int,
    pair_beam: int,
    exact_pair_beam: int,
    *,
    truth_eval: bool,
) -> Dict[str, object]:
    true_pair = stage_key_pair(key_words, 8)
    true_signature = lane_pair_signature(true_pair, 8)
    signature_scores = signature_pair_prefilter_scores(table, 8, diffs, prefilter_diffs, sample_x)
    shortlisted_signatures = [signature for _, signature in signature_scores[: max(1, signature_beam)]]
    true_signature_score = next(score for score, signature in signature_scores if signature == true_signature)
    true_signature_rank = 1 + sum(
        1 for score, signature in signature_scores if signature != true_signature and score > true_signature_score
    )

    sampled_pairs = []
    for idx, signature in enumerate(shortlisted_signatures):
        candidates, class_size, exhaustive = lane_class_candidates_for_signature(
            signature,
            8,
            pair_class_limit,
            pair_class_seed + idx,
        )
        pair_scores = []
        for pair in candidates:
            score = sampled_outer_pair_score(table, pair, diffs, prefilter_diffs, sample_x)
            pair_scores.append((score, pair))
        pair_scores.sort(key=lambda item: (item[0], item[1]), reverse=True)
        sampled_pairs.append(
            {
                "signature": signature,
                "class_size": class_size,
                "class_scanned": len(candidates),
                "class_exhaustive": exhaustive,
                "top_pairs": pair_scores[: max(1, pair_beam)],
            }
        )

    flat_pairs = []
    for item in sampled_pairs:
        for score, pair in item["top_pairs"]:
            flat_pairs.append((score, pair, item["signature"]))
    flat_pairs.sort(key=lambda item: (item[0], item[1]), reverse=True)

    exact_candidates: List[Tuple[int, int]] = []
    seen_pairs = set()
    for _, pair, _ in flat_pairs:
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            exact_candidates.append(pair)
            if len(exact_candidates) >= max(1, exact_pair_beam):
                break

    exact_scores = []
    for pair in exact_candidates:
        score, details = support_collapse_score_after_peel(table, pair, 8, OUTER_BOOTSTRAP_ROWS)
        exact_scores.append((score, pair, details))
    exact_scores.sort(key=lambda item: (item[0], item[1]))

    true_exact_score = None
    true_exact_rank = None
    if truth_eval:
        true_exact_score, _ = support_collapse_score_after_peel(table, true_pair, 8, OUTER_BOOTSTRAP_ROWS)
        true_exact_rank = 1 + sum(1 for score, pair, _ in exact_scores if pair != true_pair and score < true_exact_score)

    return {
        "true_pair": true_pair,
        "true_signature": true_signature,
        "true_signature_rank": true_signature_rank,
        "shortlisted_signatures": shortlisted_signatures,
        "signature_scores": signature_scores[: max(16, signature_beam)],
        "sampled_pairs": sampled_pairs,
        "flat_pairs": flat_pairs[: max(32, exact_pair_beam)],
        "exact_scores": exact_scores,
        "true_exact_rank": true_exact_rank,
        "true_exact_score": true_exact_score,
        "verifier_rows": list(OUTER_BOOTSTRAP_ROWS),
        "verifier_kind": "support-collapse",
        "best_pair": exact_scores[0][1] if exact_scores else None,
        "success": bool(exact_scores and exact_scores[0][1] == true_pair),
    }


def aggregate_outer_bootstrap(
    iv_candidates: Sequence[Dict[str, object]],
    per_iv_results: Sequence[Dict[str, object]],
    key_words: Sequence[int],
    diffs: Sequence[int],
    *,
    truth_eval: bool,
) -> Dict[str, object]:
    exact_cache: Dict[Tuple[int, Tuple[int, int]], Tuple[int, List[Tuple[int, int, int]]]] = {}
    union_pairs: List[Tuple[int, int]] = []
    seen_pairs = set()
    for result in per_iv_results:
        exact_scores = result["exact_scores"]
        assert isinstance(exact_scores, list)
        for _, pair, _ in exact_scores:
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                union_pairs.append(pair)

    aggregate_scores = []
    for pair in union_pairs:
        total_exact = 0
        per_iv = []
        for iv_index, iv_item in enumerate(iv_candidates):
            cache_key = (iv_index, pair)
            cached = exact_cache.get(cache_key)
            if cached is None:
                cached = support_collapse_score_after_peel(iv_item["table"], pair, 8, OUTER_BOOTSTRAP_ROWS)
                exact_cache[cache_key] = cached
            score, per_diff = cached
            total_exact += score
            per_iv.append((score, per_diff))
        aggregate_scores.append((total_exact, pair, per_iv))
    aggregate_scores.sort(key=lambda item: (item[0], item[1]))

    true_pair = stage_key_pair(key_words, 8)
    true_total = None
    true_rank = None
    if truth_eval:
        total = 0
        for iv_index, iv_item in enumerate(iv_candidates):
            cache_key = (iv_index, true_pair)
            cached = exact_cache.get(cache_key)
            if cached is None:
                cached = support_collapse_score_after_peel(iv_item["table"], true_pair, 8, OUTER_BOOTSTRAP_ROWS)
                exact_cache[cache_key] = cached
            total += cached[0]
        true_total = total
        true_rank = 1 + sum(1 for score, pair, _ in aggregate_scores if pair != true_pair and score < total)

    return {
        "union_pairs": union_pairs,
        "aggregate_scores": aggregate_scores,
        "best_pair": aggregate_scores[0][1] if aggregate_scores else None,
        "true_pair": true_pair,
        "true_total_exact": true_total,
        "true_rank": true_rank,
        "verifier_rows": list(OUTER_BOOTSTRAP_ROWS),
        "verifier_kind": "support-collapse",
        "success": bool(aggregate_scores and aggregate_scores[0][1] == true_pair),
    }


STAGE8_SAMPLE_POSITIONS = (0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 200, 233, 255)


def observed_low_groups_stage8() -> List[Tuple[int, ...]]:
    return [tuple((hi << 4) | lo for hi in range(16)) for lo in range(16)]


def transition_counts_on_high_stage8(outputs: Sequence[int], deltas: Sequence[int]) -> List[List[int]]:
    hi = [((int(x) >> 8) & 0xFF) for x in outputs]
    counts = [[0] * 256 for _ in range(256)]
    mask = 0xFFFF
    for delta in deltas:
        d = int(delta) & mask
        for pt in range(0x10000):
            counts[hi[pt]][hi[(pt + d) & mask]] += 1
    return counts


def exact_best_matching_stage8(
    source_labels: Sequence[int],
    dest_labels: Sequence[int],
    weights: Sequence[Sequence[int]],
) -> Tuple[int, Tuple[int, ...]]:
    src = tuple(int(x) & 0xFF for x in source_labels)
    dst = tuple(int(x) & 0xFF for x in dest_labels)
    table = tuple(tuple(int(weights[a][b]) for b in dst) for a in src)

    @lru_cache(maxsize=None)
    def dp(i: int, mask: int) -> Tuple[int, Tuple[int, ...]]:
        if i == 16:
            return 0, ()
        best_score = -1
        best_tail: Optional[Tuple[int, ...]] = None
        row = table[i]
        for j in range(16):
            if (mask >> j) & 1:
                continue
            tail_score, tail = dp(i + 1, mask | (1 << j))
            score = row[j] + tail_score
            if score > best_score:
                best_score = score
                best_tail = (j,) + tail
        assert best_tail is not None
        return best_score, best_tail

    score, perm = dp(0, 0)
    return score, tuple(dst[j] for j in perm)


def reconstruct_order_from_outputs_stage8(
    outputs: Sequence[int],
    observed_group_cycle: Sequence[int],
    deltas: Sequence[int],
) -> Optional[List[int]]:
    weights = transition_counts_on_high_stage8(outputs, deltas)
    groups = observed_low_groups_stage8()

    start = list(groups[int(observed_group_cycle[0]) & 0xF])
    paths = [start]
    current = start
    for i in range(15):
        dest = groups[int(observed_group_cycle[i + 1]) & 0xF]
        _, matched = exact_best_matching_stage8(current, dest, weights)
        current = list(matched)
        paths.append(current)

    _, wrap = exact_best_matching_stage8(current, tuple(start), weights)
    pos = {start[i]: i for i in range(16)}
    try:
        perm = [pos[int(wrap[i]) & 0xFF] for i in range(16)]
    except KeyError:
        return None

    seen = [False] * 16
    cycles: List[List[int]] = []
    for i in range(16):
        if seen[i]:
            continue
        cur = i
        cyc: List[int] = []
        while not seen[cur]:
            seen[cur] = True
            cyc.append(cur)
            cur = perm[cur]
        cycles.append(cyc)
    if len(cycles) != 1 or len(cycles[0]) != 16:
        return None

    top_order = cycles[0]
    ordered_groups = [[group[i] for i in top_order] for group in paths]
    order: List[int] = []
    for top_idx in range(16):
        for group_idx in range(16):
            order.append(int(ordered_groups[group_idx][top_idx]) & 0xFF)
    return order


def quotient_high_stage8(key_pair: Tuple[int, int], h: int) -> int:
    return (enc_block((int(h) & 0xFF) << 8, key_pair, 8) >> 8) & 0xFF


def canon_cycle_stage8(seq: Sequence[int]) -> Tuple[int, ...]:
    out = [int(v) & 0xF for v in seq]
    if 0 in out:
        idx = out.index(0)
        out = out[idx:] + out[:idx]
    return tuple(out)


def stage8_projected_representatives() -> Dict[Tuple[int, ...], List[Tuple[int, int]]]:
    global _STAGE8_PROJECTED_REPS
    if _STAGE8_PROJECTED_REPS is not None:
        return _STAGE8_PROJECTED_REPS

    invisible = P_INVISIBLE_BITS_STAGE8
    visible = tuple(bit for bit in range(32) if bit not in invisible)
    reps: Dict[Tuple[int, ...], List[Tuple[int, int]]] = {}
    total_masks = 1 << len(visible)
    step = max(1, total_masks // 256)
    for mask in range(total_masks):
        if (mask % step) == 0 or mask + 1 == total_masks:
            _progress_update("stage8-reps", mask + 1, total_masks)
        k0 = 0
        k1 = 0
        for i, bit in enumerate(visible):
            if ((mask >> i) & 1) == 0:
                continue
            if bit < 16:
                k0 |= 1 << bit
            else:
                k1 |= 1 << (bit - 16)
        p = tuple(quotient_high_stage8((k0, k1), lo) & 0xF for lo in range(16))
        reps.setdefault(p, []).append((k0, k1))
    _progress_finish("stage8-reps")
    _STAGE8_PROJECTED_REPS = reps
    return reps


@lru_cache(maxsize=None)
def projected_representatives(stage_idx: int, canonicalize: bool) -> Dict[Tuple[int, ...], List[Tuple[int, int]]]:
    invisible = P_INVISIBLE_BITS[stage_idx]
    visible = tuple(bit for bit in range(32) if bit not in invisible)
    reps: Dict[Tuple[int, ...], List[Tuple[int, int]]] = {}
    total_masks = 1 << len(visible)
    step = max(1, total_masks // 256)
    label = f"stage{stage_idx}-reps"
    for mask in range(total_masks):
        if (mask % step) == 0 or mask + 1 == total_masks:
            _progress_update(label, mask + 1, total_masks)
        k0 = 0
        k1 = 0
        for i, bit in enumerate(visible):
            if ((mask >> i) & 1) == 0:
                continue
            if bit < 16:
                k0 |= 1 << bit
            else:
                k1 |= 1 << (bit - 16)
        p = tuple(((enc_block((lo & 0xFF) << 8, (k0, k1), stage_idx) >> 8) & 0xF) for lo in range(16))
        if canonicalize:
            p = canon_cycle_stage8(p)
        reps.setdefault(p, []).append((k0, k1))
    _progress_finish(label)
    return reps


def top_projected_cycles(
    outputs: Sequence[int],
    stage_idx: int,
    deltas: Sequence[int],
    topn: int,
) -> List[Tuple[int, Tuple[int, ...]]]:
    flat = stage8_group_mass(outputs, deltas)
    scored: List[Tuple[int, Tuple[int, ...]]] = []
    if stage_idx == 8:
        cycle_family = list(projected_representatives(stage_idx, False).keys())
    else:
        cycle_family = []
        for base in projected_representatives(stage_idx, True).keys():
            for shift in range(16):
                cycle_family.append(tuple((int(value) + shift) & 0xF for value in base))
    total_cycles = len(cycle_family)
    step = max(1, total_cycles // 256) if total_cycles else 1
    label = f"stage{stage_idx}-cycles"
    for index, cycle in enumerate(cycle_family, start=1):
        if (index % step) == 0 or index == total_cycles:
            _progress_update(label, index, total_cycles)
        edges = tuple((((int(cycle[i]) & 0xF) << 4) | (int(cycle[(i + 1) & 15]) & 0xF)) for i in range(16))
        score = 0
        for idx in edges:
            score += flat[idx]
        scored.append((score, cycle))
    _progress_finish(label)
    return heapq.nlargest(max(1, topn), scored, key=lambda item: (item[0], item[1]))


def quotient_high_generic(key_pair: Tuple[int, int], stage_idx: int, h: int) -> int:
    return (enc_block((int(h) & 0xFF) << 8, key_pair, stage_idx) >> 8) & 0xFF


def exact_key_candidates_no_translation(
    stage_idx: int,
    order_infos: Sequence[Tuple[Tuple[int, ...], Tuple[int, ...]]],
    observed_cycle: Sequence[int],
) -> List[Tuple[Tuple[int, int], Tuple[int, ...]]]:
    sample_map = order_target_maps_stage8(order_infos)
    rep_map = projected_representatives(stage_idx, False)
    invisible = P_INVISIBLE_BITS[stage_idx]

    invisible_masks: List[Tuple[int, int]] = []
    for mask in range(1 << len(invisible)):
        k0_add = 0
        k1_add = 0
        for i, bit in enumerate(invisible):
            if ((mask >> i) & 1) == 0:
                continue
            if bit < 16:
                k0_add |= 1 << bit
            else:
                k1_add |= 1 << (bit - 16)
        invisible_masks.append((k0_add, k1_add))

    seen: set[Tuple[int, int, Tuple[int, ...]]] = set()
    out: List[Tuple[Tuple[int, int], Tuple[int, ...]]] = []
    observed = tuple(int(v) & 0xF for v in observed_cycle)
    base_keys = list(rep_map.get(observed, ()))
    total_work = max(1, len(base_keys) * max(1, len(invisible_masks)))
    work_index = 0
    label = f"stage{stage_idx}-cand0"
    for base_k0, base_k1 in base_keys:
        for add_k0, add_k1 in invisible_masks:
            work_index += 1
            k0 = base_k0 | add_k0
            k1 = base_k1 | add_k1
            _progress_update(label, work_index, total_work, f"testing [{k0:04X} {k1:04X}]")
            sample_q = tuple(quotient_high_generic((k0, k1), stage_idx, h) for h in STAGE8_SAMPLE_POSITIONS)
            matched_targets = sample_map.get(sample_q)
            if not matched_targets:
                continue
            full_q = tuple(quotient_high_generic((k0, k1), stage_idx, h) for h in range(256))
            for full_target, _cycle in matched_targets:
                if full_q != full_target:
                    continue
                dedup = (k0, k1, full_target)
                if dedup in seen:
                    continue
                seen.add(dedup)
                out.append(((k0, k1), full_target))
    _progress_finish(label)
    return out


def exact_key_candidates_with_translation(
    stage_idx: int,
    order_infos: Sequence[Tuple[Tuple[int, ...], Tuple[int, ...]]],
    observed_cycle: Sequence[int],
) -> List[Tuple[Tuple[int, int], int, Tuple[int, ...]]]:
    sample_map = order_target_maps_stage8(order_infos)
    rep_map = projected_representatives(stage_idx, True)
    invisible = P_INVISIBLE_BITS[stage_idx]

    invisible_masks: List[Tuple[int, int]] = []
    for mask in range(1 << len(invisible)):
        k0_add = 0
        k1_add = 0
        for i, bit in enumerate(invisible):
            if ((mask >> i) & 1) == 0:
                continue
            if bit < 16:
                k0_add |= 1 << bit
            else:
                k1_add |= 1 << (bit - 16)
        invisible_masks.append((k0_add, k1_add))

    seen: set[Tuple[int, int, int, Tuple[int, ...]]] = set()
    out: List[Tuple[Tuple[int, int], int, Tuple[int, ...]]] = []
    observed = tuple(int(v) & 0xF for v in observed_cycle)
    base_keys_by_tl: List[Tuple[int, List[Tuple[int, int]]]] = []
    for tl in range(16):
        projected_cycle = tuple((value - tl) & 0xF for value in observed)
        if 0 in projected_cycle:
            idx = projected_cycle.index(0)
            projected_cycle = projected_cycle[idx:] + projected_cycle[:idx]
        base_keys = rep_map.get(tuple(projected_cycle), ())
        if not base_keys:
            continue
        base_keys_by_tl.append((tl, list(base_keys)))
    total_work = sum(len(base_keys) for _, base_keys in base_keys_by_tl) * max(1, len(invisible_masks))
    total_work = max(1, total_work)
    work_index = 0
    label = f"stage{stage_idx}-cand1"
    for tl, base_keys in base_keys_by_tl:
        for base_k0, base_k1 in base_keys:
            for add_k0, add_k1 in invisible_masks:
                work_index += 1
                k0 = base_k0 | add_k0
                k1 = base_k1 | add_k1
                _progress_update(label, work_index, total_work, f"testing [{k0:04X} {k1:04X}]")
                sample_q = tuple(quotient_high_generic((k0, k1), stage_idx, h) for h in STAGE8_SAMPLE_POSITIONS)
                matched_targets = None
                found_tau = None
                for tau_hi in range(16):
                    tau = (tau_hi << 4) | tl
                    shifted = tuple((value + tau) & 0xFF for value in sample_q)
                    hits = sample_map.get(shifted)
                    if hits:
                        matched_targets = hits
                        found_tau = tau
                        break
                if matched_targets is None or found_tau is None:
                    continue
                full_q = tuple(quotient_high_generic((k0, k1), stage_idx, h) for h in range(256))
                shifted_full = tuple((value + found_tau) & 0xFF for value in full_q)
                for full_target, _cycle in matched_targets:
                    if shifted_full != full_target:
                        continue
                    dedup = (k0, k1, found_tau, full_target)
                    if dedup in seen:
                        continue
                    seen.add(dedup)
                    out.append(((k0, k1), found_tau, full_target))
    _progress_finish(label)
    return out


def attacked_position_projected_scan(
    current_outputs: Sequence[int],
    stage_idx: int,
    diffs: Sequence[int],
    *,
    low_beam: int,
    cycle_beam: int,
) -> Dict[str, object]:
    if stage_idx < 1 or stage_idx > 7:
        raise ValueError("stage_idx must be in 1..7 for attacked-position projected scan")

    low_ranked = exact_low_byte_scan(current_outputs, topn=max(1, low_beam))
    candidates: List[Dict[str, object]] = []
    seen: set[Tuple[int, int, int]] = set()

    total_lows = max(1, min(len(low_ranked), max(1, low_beam)))
    for low_index, low_item in enumerate(low_ranked[: max(1, low_beam)], start=1):
        _progress_update(f"stage{stage_idx}-attack", low_index, total_lows)
        low = int(low_item["low"]) & 0xFF
        corrected = subtract_translation(current_outputs, low)
        cycle_scores = top_projected_cycles(corrected, stage_idx, diffs, max(1, cycle_beam))
        for cycle_rank, (cycle_score, cycle) in enumerate(cycle_scores[: max(1, cycle_beam)], start=1):
            for rot_idx, rotated_cycle in enumerate(positional_rotations_stage8(cycle)):
                order = reconstruct_order_from_outputs_stage8(corrected, rotated_cycle, diffs)
                if order is None:
                    continue
                hits = exact_key_candidates_with_translation(stage_idx, [(tuple(rotated_cycle), tuple(order))], tuple(rotated_cycle))
                for pair, tau, _full_target in hits:
                    state_word = ((int(tau) & 0xFF) << 8) | low
                    dedup = (int(pair[0]) & 0xFFFF, int(pair[1]) & 0xFFFF, state_word)
                    if dedup in seen:
                        continue
                    seen.add(dedup)
                    reduced_table = subtract_translation(current_outputs, state_word)
                    verifier_score, verifier_details = support_collapse_score_after_peel(
                        reduced_table,
                        pair,
                        stage_idx,
                        OUTER_BOOTSTRAP_ROWS,
                    )
                    candidates.append(
                        {
                            "pair": (int(pair[0]) & 0xFFFF, int(pair[1]) & 0xFFFF),
                            "state_word": state_word,
                            "low": low,
                            "high": (state_word >> 8) & 0xFF,
                            "cycle": tuple(int(v) & 0xF for v in rotated_cycle),
                            "cycle_rank": cycle_rank,
                            "cycle_score": int(cycle_score),
                            "rotation": rot_idx,
                            "verifier_score": int(verifier_score),
                            "verifier_details": verifier_details,
                        }
                    )

    candidates.sort(
        key=lambda item: (
            int(item["verifier_score"]),
            int(item["cycle_rank"]),
            -int(item["cycle_score"]),
            tuple(int(x) for x in item["pair"]),
            int(item["state_word"]),
        )
    )
    _progress_finish(f"stage{stage_idx}-attack")
    return {
        "low_ranked": low_ranked,
        "candidates": candidates,
        "best": candidates[0] if candidates else None,
    }


def recursive_public_context_recovery(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    known_outer_keys: Dict[int, Tuple[int, int]],
    target_stage: int,
    diffs: Sequence[int],
    *,
    low_beam: int,
    cycle_beam: int,
) -> Dict[str, object]:
    if target_stage < 1 or target_stage > 7:
        raise ValueError("target_stage must be in 1..7")
    if 8 not in known_outer_keys:
        raise ValueError("known_outer_keys must include stage 8")

    ctx = ctx_after_prefix(key_words, iv_words, prefix_words)
    current_outputs = peel_current_forward_stage_table(next_word_table(ctx, key_words), known_outer_keys[8], 8)
    stage_rows: List[Dict[str, object]] = []
    recovered_keys: Dict[int, Tuple[int, int]] = dict(known_outer_keys)
    recovered_states: Dict[int, int] = {}
    state_words = ctx["state"]
    assert isinstance(state_words, list)

    for stage_idx in range(7, target_stage - 1, -1):
        scan = attacked_position_projected_scan(
            current_outputs,
            stage_idx,
            diffs,
            low_beam=low_beam,
            cycle_beam=cycle_beam,
        )
        best = scan["best"]
        assert isinstance(best, dict) or best is None
        true_pair = stage_key_pair(key_words, stage_idx)
        true_state = int(state_words[stage_idx]) & 0xFFFF
        candidates = scan["candidates"]
        assert isinstance(candidates, list)
        true_rank = None
        for idx, item in enumerate(candidates, start=1):
            if tuple(item["pair"]) == true_pair and int(item["state_word"]) == true_state:
                true_rank = idx
                break
        low_ranked = scan["low_ranked"]
        assert isinstance(low_ranked, list)
        low_best_support = int(low_ranked[0]["total_support"]) if low_ranked else None
        low_second_support = int(low_ranked[1]["total_support"]) if len(low_ranked) > 1 else None
        low_gap = (
            None
            if low_best_support is None or low_second_support is None
            else int(low_second_support) - int(low_best_support)
        )
        candidate_pairs = sorted({tuple(int(x) for x in item["pair"]) for item in candidates})
        verifier_gap = None
        if len(candidates) > 1:
            verifier_gap = int(candidates[1]["verifier_score"]) - int(candidates[0]["verifier_score"])

        stage_rows.append(
            {
                "stage": stage_idx,
                "true_pair": true_pair,
                "true_state": true_state,
                "true_rank": true_rank,
                "candidate_count": len(candidates),
                "candidate_pairs": candidate_pairs,
                "low_best_support": low_best_support,
                "low_second_support": low_second_support,
                "low_gap": low_gap,
                "verifier_gap": verifier_gap,
                "best": best,
                "top": candidates[: min(8, len(candidates))],
            }
        )

        if best is None:
            break

        best_pair = best["pair"]
        best_state = int(best["state_word"]) & 0xFFFF
        recovered_keys[stage_idx] = best_pair  # type: ignore[assignment]
        recovered_states[stage_idx + 1] = best_state

        if stage_idx > target_stage:
            reduced = subtract_translation(current_outputs, best_state)
            current_outputs = peel_current_forward_stage_table(reduced, best_pair, stage_idx)

    return {
        "iv": words_to_hex(iv_words),
        "prefix": list(prefix_words),
        "target_stage": target_stage,
        "stage_rows": stage_rows,
        "recovered_keys": recovered_keys,
        "recovered_states": recovered_states,
    }


def build_recursive_contexts(
    iv7_values: Sequence[int],
    prefix_values: Sequence[int],
    *,
    include_empty_prefix: bool,
    empty_only: bool = False,
) -> List[Tuple[int, Tuple[int, ...]]]:
    contexts: List[Tuple[int, Tuple[int, ...]]] = []
    if empty_only:
        for iv7 in iv7_values:
            contexts.append((int(iv7) & 0xFFFF, ()))
        return contexts
    if include_empty_prefix:
        for iv7 in iv7_values:
            contexts.append((int(iv7) & 0xFFFF, ()))
    for iv7 in iv7_values:
        iv7w = int(iv7) & 0xFFFF
        for prefix in prefix_values:
            contexts.append((iv7w, (int(prefix) & 0xFFFF,)))
    return contexts


def candidate_pair_intersections(
    entries: Sequence[Dict[str, object]],
    *,
    topn: int,
) -> List[Dict[str, object]]:
    intersections: List[Dict[str, object]] = []
    running: Optional[set[Tuple[int, int]]] = None
    used = 0
    true_pair = None
    for entry in entries:
        candidate_pairs = entry["candidate_pairs"]
        assert isinstance(candidate_pairs, list)
        if not candidate_pairs:
            continue
        current = {tuple(int(x) for x in pair) for pair in candidate_pairs}
        running = current if running is None else (running & current)
        used += 1
        if true_pair is None:
            true_value = entry.get("true_pair")
            if isinstance(true_value, tuple):
                true_pair = tuple(int(x) for x in true_value)
        intersections.append(
            {
                "contexts_used": used,
                "intersection_size": len(running),
                "pairs": sorted(running)[:8],
                "true_survives": (true_pair in running) if true_pair is not None else None,
                "context": entry["label"],
            }
        )
        if used >= topn:
            break
    return intersections
def evaluate_context_search_entry(
    key_words: Sequence[int],
    target_stage: int,
    iv7: int,
    prefix_words: Sequence[int],
    diffs: Sequence[int],
    *,
    known_outer_states: Dict[int, int],
    oracle_reduced: bool,
    cycle_top: int,
    overall_top: int,
    low_beam: int,
) -> Dict[str, object]:
    iv_words = iv_words_from_iv7(iv7)
    prefix_tuple = tuple(int(word) & 0xFFFF for word in prefix_words)
    label = f"iv7={int(iv7) & 0xFFFF:04X} prefix={format_optional_prefix(prefix_tuple)}"

    if target_stage == 8:
        result = k8_projected_cycle_bootstrap(
            key_words,
            iv_words,
            prefix_tuple,
            diffs,
            cycle_top=max(1, cycle_top),
            overall_top=max(1, overall_top),
            truth_eval=True,
        )
        refined = result["refined"]
        assert isinstance(refined, list)
        cycle_scores = result["cycle_scores"]
        assert isinstance(cycle_scores, list)
        cycle_gap = None
        if cycle_scores:
            cycle_gap = int(cycle_scores[0][0]) - int(cycle_scores[1][0]) if len(cycle_scores) > 1 else int(cycle_scores[0][0])
        candidate_pairs = [tuple(int(x) for x in pair) for _score, pair, *_rest in refined]
        best_score = int(refined[0][0]) if refined else (1 << 60)
        return {
            "kind": "stage8",
            "label": label,
            "iv7": int(iv7) & 0xFFFF,
            "prefix": prefix_tuple,
            "candidate_pairs": candidate_pairs,
            "candidate_count": len(candidate_pairs),
            "reached_target": bool(refined),
            "ready_stage": 8,
            "cycle_gap": cycle_gap,
            "best_score": best_score,
            "true_pair": tuple(int(x) for x in result["true_pair"]),
            "true_rank": result["true_rank"],
            "result": result,
        }

    reduced_states = dict(known_outer_states)
    if oracle_reduced and target_stage < 8:
        ctx = ctx_after_prefix(key_words, iv_words, prefix_tuple)
        state_words = ctx["state"]
        assert isinstance(state_words, list)
        for stage in range(target_stage + 1, 9):
            reduced_states[stage] = int(state_words[stage - 1]) & 0xFFFF

    has_reduced_state = all(stage in reduced_states for stage in range(target_stage + 1, 9))
    if has_reduced_state:
        result = reduced_projected_cycle_scan(
            key_words,
            iv_words,
            prefix_tuple,
            target_stage,
            reduced_states,
            diffs,
            cycle_top=max(1, cycle_top),
            overall_top=max(1, overall_top),
            truth_eval=True,
        )
        refined = result["refined"]
        assert isinstance(refined, list)
        cycle_scores = result["cycle_scores"]
        assert isinstance(cycle_scores, list)
        cycle_gap = None
        if cycle_scores:
            cycle_gap = int(cycle_scores[0][0]) - int(cycle_scores[1][0]) if len(cycle_scores) > 1 else int(cycle_scores[0][0])
        candidate_pairs = [tuple(int(x) for x in pair) for _score, pair, *_rest in refined]
        best_score = int(refined[0][0]) if refined else (1 << 60)
        return {
            "kind": "reduced",
            "label": label,
            "iv7": int(iv7) & 0xFFFF,
            "prefix": prefix_tuple,
            "candidate_pairs": candidate_pairs,
            "candidate_count": len(candidate_pairs),
            "reached_target": bool(refined),
            "ready_stage": target_stage,
            "cycle_gap": cycle_gap,
            "best_score": best_score,
            "true_pair": tuple(int(x) for x in result["true_pair"]),
            "true_rank": result["true_rank"],
            "result": result,
        }

    known_outer_keys = {stage_idx: stage_key_pair(key_words, stage_idx) for stage_idx in range(target_stage + 1, 9)}
    result = recursive_public_context_recovery(
        key_words,
        iv_words,
        prefix_tuple,
        known_outer_keys,
        target_stage,
        diffs,
        low_beam=max(1, low_beam),
        cycle_beam=max(1, cycle_top),
    )
    stage_rows = result["stage_rows"]
    assert isinstance(stage_rows, list)
    reached_rows = [row for row in stage_rows if row["best"] is not None]
    reached_target = bool(reached_rows and int(reached_rows[-1]["stage"]) == target_stage)
    focus_row = None
    if reached_target:
        focus_row = reached_rows[-1]
    elif reached_rows:
        focus_row = reached_rows[-1]
    ready_stage = int(focus_row["stage"]) if focus_row is not None else 8
    candidate_pairs: List[Tuple[int, int]] = []
    true_pair = stage_key_pair(key_words, target_stage)
    true_rank = None
    best_score = 1 << 60
    low_gap = None
    verifier_gap = None
    if reached_target and focus_row is not None:
        candidate_pairs = [tuple(int(x) for x in pair) for pair in focus_row["candidate_pairs"]]
        true_rank = focus_row["true_rank"]
        best = focus_row["best"]
        assert isinstance(best, dict)
        best_score = int(best["verifier_score"])
        low_gap = focus_row["low_gap"]
        verifier_gap = focus_row["verifier_gap"]
    elif focus_row is not None:
        best = focus_row["best"]
        if isinstance(best, dict):
            best_score = int(best["verifier_score"])
            low_gap = focus_row["low_gap"]
            verifier_gap = focus_row["verifier_gap"]
    return {
        "kind": "recursive",
        "label": label,
        "iv7": int(iv7) & 0xFFFF,
        "prefix": prefix_tuple,
        "candidate_pairs": candidate_pairs,
        "candidate_count": len(candidate_pairs),
        "reached_target": reached_target,
        "ready_stage": ready_stage,
        "cycle_gap": None,
        "best_score": best_score,
        "low_gap": low_gap,
        "verifier_gap": verifier_gap,
        "true_pair": true_pair,
        "true_rank": true_rank,
        "result": result,
    }


def recursive_context_search(
    key_words: Sequence[int],
    target_stage: int,
    diffs: Sequence[int],
    *,
    iv7_values: Sequence[int],
    prefix_values: Sequence[int],
    include_empty_prefix: bool,
    empty_only: bool,
    known_outer_states: Dict[int, int],
    oracle_reduced: bool,
    cycle_top: int,
    overall_top: int,
    low_beam: int,
    topn: int,
) -> Dict[str, object]:
    contexts = build_recursive_contexts(
        iv7_values,
        prefix_values,
        include_empty_prefix=include_empty_prefix,
        empty_only=empty_only,
    )
    entries: List[Dict[str, object]] = []
    total = len(contexts)
    for idx, (iv7, prefix_words) in enumerate(contexts, start=1):
        entry = evaluate_context_search_entry(
            key_words,
            target_stage,
            iv7,
            prefix_words,
            diffs,
            known_outer_states=known_outer_states,
            oracle_reduced=oracle_reduced,
            cycle_top=cycle_top,
            overall_top=overall_top,
            low_beam=low_beam,
        )
        entry["index"] = idx
        entries.append(entry)

    def sort_key(entry: Dict[str, object]) -> Tuple[object, ...]:
        reached_target = bool(entry["reached_target"])
        candidate_count = int(entry["candidate_count"])
        best_score = int(entry["best_score"])
        ready_stage = int(entry["ready_stage"])
        cycle_gap = entry.get("cycle_gap")
        verifier_gap = entry.get("verifier_gap")
        low_gap = entry.get("low_gap")
        return (
            0 if reached_target else 1,
            0 if candidate_count > 0 else 1,
            candidate_count if candidate_count > 0 else (1 << 30),
            ready_stage,
            -int(verifier_gap) if verifier_gap is not None else 0,
            -int(low_gap) if low_gap is not None else 0,
            best_score,
            -int(cycle_gap) if cycle_gap is not None else 0,
            int(entry["iv7"]),
            tuple(int(x) for x in entry["prefix"]),
        )

    entries.sort(key=sort_key)
    intersections = candidate_pair_intersections(entries, topn=max(1, topn))
    return {
        "target_stage": target_stage,
        "contexts_scanned": total,
        "entries": entries,
        "intersections": intersections,
        "known_outer_states": dict(known_outer_states),
        "mode": (
            "reduced"
            if target_stage < 8 and (
                oracle_reduced or all(stage in known_outer_states for stage in range(target_stage + 1, 9))
            )
            else ("stage8" if target_stage == 8 else "recursive")
        ),
    }


def reduced_projected_cycle_scan(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    target_stage: int,
    known_outer_states: Dict[int, int],
    diffs: Sequence[int],
    *,
    cycle_top: int,
    overall_top: int,
    truth_eval: bool,
) -> Dict[str, object]:
    if target_stage < 1 or target_stage > 7:
        raise ValueError("target_stage must be in 1..7 for reduced projected-cycle scan")

    prepared = prepare_forward_right_stage_table(
        key_words,
        iv_words,
        prefix_words,
        target_stage,
        known_outer_states,
    )
    table = prepared["table"]
    assert isinstance(table, list)
    true_pair = stage_key_pair(key_words, target_stage)
    scored_cycles = top_projected_cycles(table, target_stage, diffs, max(1, overall_top))

    candidates: List[Tuple[Tuple[int, int], Tuple[int, ...], Tuple[int, ...], int]] = []
    seen: set[Tuple[int, int]] = set()
    selected_cycles = scored_cycles[: max(1, overall_top)]
    total_cycles = max(1, len(selected_cycles) * 16)
    rotation_index = 0
    for cycle_score, cycle in selected_cycles:
        for rotated_cycle in positional_rotations_stage8(cycle):
            rotation_index += 1
            _progress_update(f"stage{target_stage}-reduced", rotation_index, total_cycles)
            order = reconstruct_order_from_outputs_stage8(table, rotated_cycle, diffs)
            if order is None:
                continue
            key_hits = exact_key_candidates_no_translation(target_stage, [(tuple(rotated_cycle), tuple(order))], tuple(rotated_cycle))
            for key_pair, full_target in key_hits:
                if key_pair in seen:
                    continue
                seen.add(key_pair)
                candidates.append((key_pair, tuple(rotated_cycle), tuple(full_target), cycle_score))
    _progress_finish(f"stage{target_stage}-reduced")

    refined = []
    total_candidates = len(candidates)
    for candidate_index, (key_pair, cycle, order, cycle_score) in enumerate(candidates, start=1):
        if total_candidates:
            _progress_update(f"stage{target_stage}-verify", candidate_index, total_candidates, f"testing [{int(key_pair[0]):04X} {int(key_pair[1]):04X}]")
        score, details = support_collapse_score_after_peel(table, key_pair, target_stage, OUTER_BOOTSTRAP_ROWS)
        refined.append((score, key_pair, cycle, cycle_score, details))
    _progress_finish(f"stage{target_stage}-verify")
    refined.sort(key=lambda item: (item[0], item[1]))

    true_rank = None
    true_score = None
    true_details = None
    if truth_eval:
        true_score, true_details = support_collapse_score_after_peel(table, true_pair, target_stage, OUTER_BOOTSTRAP_ROWS)
        true_rank = 1 + sum(1 for score, pair, *_ in refined if pair != true_pair and score < true_score)

    return {
        "iv": words_to_hex(iv_words),
        "prefix": list(prefix_words),
        "target_stage": target_stage,
        "true_pair": true_pair,
        "cycle_scores": scored_cycles[: max(1, cycle_top)],
        "candidate_count": len(candidates),
        "refined": refined,
        "best_pair": refined[0][1] if refined else None,
        "true_rank": true_rank,
        "true_score": true_score,
        "true_details": true_details,
        "success": bool(refined and refined[0][1] == true_pair),
    }


def stage8_cycle_family() -> List[Tuple[int, ...]]:
    return list(stage8_projected_representatives().keys())


@lru_cache(maxsize=None)
def stage8_cycle_edges(cycle: Tuple[int, ...]) -> Tuple[int, ...]:
    return tuple((((int(cycle[i]) & 0xF) << 4) | (int(cycle[(i + 1) & 15]) & 0xF)) for i in range(16))


def stage8_group_mass(outputs: Sequence[int], deltas: Sequence[int]) -> List[int]:
    flat = [0] * 256
    mask = 0xFFFF
    for delta in deltas:
        d = int(delta) & mask
        for pt in range(0x10000):
            a = int(outputs[pt]) & mask
            b = int(outputs[(pt + d) & mask]) & mask
            ga = (a >> 8) & 0xF
            gb = (b >> 8) & 0xF
            flat[(ga << 4) | gb] += 1
    return flat


def top_stage8_cycles(outputs: Sequence[int], deltas: Sequence[int], topn: int) -> List[Tuple[int, Tuple[int, ...]]]:
    flat = stage8_group_mass(outputs, deltas)
    scored: List[Tuple[int, Tuple[int, ...]]] = []
    cycle_family = stage8_cycle_family()
    total_cycles = len(cycle_family)
    step = max(1, total_cycles // 256) if total_cycles else 1
    for index, cycle in enumerate(cycle_family, start=1):
        if (index % step) == 0 or index == total_cycles:
            _progress_update("stage8-cycles", index, total_cycles)
        score = 0
        for idx in stage8_cycle_edges(cycle):
            score += flat[idx]
        scored.append((score, cycle))
    _progress_finish("stage8-cycles")
    return heapq.nlargest(max(1, topn), scored, key=lambda item: (item[0], item[1]))


def positional_rotations_stage8(cycle: Sequence[int]) -> List[Tuple[int, ...]]:
    cyc = tuple(int(v) & 0xF for v in cycle)
    return [cyc[shift:] + cyc[:shift] for shift in range(16)]


def build_rotated_order_targets_stage8(order: Sequence[int]) -> List[Tuple[int, ...]]:
    return [
        tuple(int(order[((top + r) & 0xF) * 16 + low]) & 0xFF for top in range(16) for low in range(16))
        for r in range(16)
    ]


@lru_cache(maxsize=None)
def sample_targets_for_order_stage8(order: Tuple[int, ...]) -> List[Tuple[int, ...]]:
    rotated = build_rotated_order_targets_stage8(order)
    return [tuple(rot[h] for h in STAGE8_SAMPLE_POSITIONS) for rot in rotated]


def order_target_maps_stage8(
    order_infos: Sequence[Tuple[Tuple[int, ...], Tuple[int, ...]]]
) -> Dict[Tuple[int, ...], List[Tuple[Tuple[int, ...], Tuple[int, ...]]]]:
    sample_map: Dict[Tuple[int, ...], List[Tuple[Tuple[int, ...], Tuple[int, ...]]]] = {}
    for cycle, order in order_infos:
        full_targets = build_rotated_order_targets_stage8(order)
        sample_targets = sample_targets_for_order_stage8(tuple(order))
        for sample_target, full_target in zip(sample_targets, full_targets):
            sample_map.setdefault(sample_target, []).append((full_target, cycle))
    return sample_map


def exact_stage8_key_candidates(
    order_infos: Sequence[Tuple[Tuple[int, ...], Tuple[int, ...]]],
    observed_cycle: Sequence[int],
) -> List[Tuple[Tuple[int, int], int, Tuple[int, ...]]]:
    sample_map = order_target_maps_stage8(order_infos)
    rep_map = stage8_projected_representatives()

    invisible_masks: List[Tuple[int, int]] = []
    for mask in range(1 << len(P_INVISIBLE_BITS_STAGE8)):
        k0_add = 0
        k1_add = 0
        for i, bit in enumerate(P_INVISIBLE_BITS_STAGE8):
            if ((mask >> i) & 1) == 0:
                continue
            if bit < 16:
                k0_add |= 1 << bit
            else:
                k1_add |= 1 << (bit - 16)
        invisible_masks.append((k0_add, k1_add))

    seen: set[Tuple[int, int, int, Tuple[int, ...]]] = set()
    out: List[Tuple[Tuple[int, int], int, Tuple[int, ...]]] = []
    base_keys = list(rep_map.get(tuple(int(v) & 0xF for v in observed_cycle), ()))
    total_work = max(1, len(base_keys) * max(1, len(invisible_masks)))
    work_index = 0
    for base_k0, base_k1 in base_keys:
        for add_k0, add_k1 in invisible_masks:
            work_index += 1
            k0 = base_k0 | add_k0
            k1 = base_k1 | add_k1
            _progress_update("stage8-cands", work_index, total_work, f"testing [{k0:04X} {k1:04X}]")
            sample_q = tuple(quotient_high_stage8((k0, k1), h) for h in STAGE8_SAMPLE_POSITIONS)
            matched_targets = None
            found_tau = None
            for tau_hi in range(16):
                tau = tau_hi << 4
                shifted = tuple((value + tau) & 0xFF for value in sample_q)
                hits = sample_map.get(shifted)
                if hits:
                    matched_targets = hits
                    found_tau = tau
                    break
            if matched_targets is None or found_tau is None:
                continue
            full_q = tuple(quotient_high_stage8((k0, k1), h) for h in range(256))
            shifted_full = tuple((value + found_tau) & 0xFF for value in full_q)
            for full_target, _cycle in matched_targets:
                if shifted_full != full_target:
                    continue
                dedup = (k0, k1, found_tau, full_target)
                if dedup in seen:
                    continue
                seen.add(dedup)
                out.append(((k0, k1), found_tau, full_target))
    _progress_finish("stage8-cands")
    return out


def k8_projected_cycle_bootstrap(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    diffs: Sequence[int],
    *,
    cycle_top: int,
    overall_top: int,
    truth_eval: bool,
) -> Dict[str, object]:
    ctx = ctx_after_prefix(key_words, iv_words, prefix_words)
    table = next_word_table(ctx, key_words)
    true_pair = stage_key_pair(key_words, 8)
    scored_cycles = top_stage8_cycles(table, diffs, max(1, overall_top))

    candidates: List[Tuple[Tuple[int, int], int, Tuple[int, ...], Tuple[int, ...], int]] = []
    seen: set[Tuple[int, int]] = set()
    selected_cycles = scored_cycles[: max(1, overall_top)]
    total_rotations = max(1, len(selected_cycles) * 16)
    rotation_index = 0
    for cycle_score, cycle in selected_cycles:
        for rotated_cycle in positional_rotations_stage8(cycle):
            rotation_index += 1
            _progress_update("stage8-rot", rotation_index, total_rotations)
            order = reconstruct_order_from_outputs_stage8(table, rotated_cycle, diffs)
            if order is None:
                continue
            key_hits = exact_stage8_key_candidates([(tuple(rotated_cycle), tuple(order))], tuple(rotated_cycle))
            for key_pair, tau, full_target in key_hits:
                if key_pair in seen:
                    continue
                seen.add(key_pair)
                candidates.append((key_pair, tau, tuple(rotated_cycle), tuple(full_target), cycle_score))
    _progress_finish("stage8-rot")

    refined = []
    total_candidates = len(candidates)
    for candidate_index, (key_pair, tau, cycle, order, cycle_score) in enumerate(candidates, start=1):
        if total_candidates:
            _progress_update("stage8-verify", candidate_index, total_candidates, f"testing [{int(key_pair[0]):04X} {int(key_pair[1]):04X}]")
        score, details = support_collapse_score_after_peel(table, key_pair, 8, OUTER_BOOTSTRAP_ROWS)
        refined.append((score, key_pair, tau, cycle, cycle_score, details))
    _progress_finish("stage8-verify")
    refined.sort(key=lambda item: (item[0], item[1]))

    true_rank = None
    true_score = None
    if truth_eval:
        true_score, true_details = support_collapse_score_after_peel(table, true_pair, 8, OUTER_BOOTSTRAP_ROWS)
        true_rank = 1 + sum(1 for score, pair, *_ in refined if pair != true_pair and score < true_score)
    else:
        true_details = None

    return {
        "iv": words_to_hex(iv_words),
        "prefix": list(prefix_words),
        "true_pair": true_pair,
        "cycle_scores": scored_cycles[: max(1, cycle_top)],
        "candidate_count": len(candidates),
        "refined": refined,
        "best_pair": refined[0][1] if refined else None,
        "true_rank": true_rank,
        "true_score": true_score,
        "true_details": true_details,
        "success": bool(refined and refined[0][1] == true_pair),
    }


def invert_table(table: Sequence[int]) -> List[int]:
    inv = [0] * 0x10000
    for x, y in enumerate(table):
        inv[int(y) & 0xFFFF] = x & 0xFFFF
    return inv


def nibble2(x: int) -> int:
    return (x >> 8) & 0xF


def lane_word_signature_k0(word: int, stage_idx: int) -> Tuple[int, int]:
    key2, _ = derive_key23(word, 0, stage_idx)
    return nibble2(word), nibble2(key2)


def lane_word_signature_k1(word: int, stage_idx: int) -> Tuple[int, int]:
    _, key3 = derive_key23(0, word, stage_idx)
    return nibble2(word), nibble2(key3)


def lane_pair_signature(pair: Tuple[int, int], stage_idx: int) -> Tuple[int, int, int, int]:
    left = lane_word_signature_k0(pair[0], stage_idx)
    right = lane_word_signature_k1(pair[1], stage_idx)
    return left[0], left[1], right[0], right[1]


def lane_buckets_for_stage(stage_idx: int) -> Tuple[Dict[Tuple[int, int], List[int]], Dict[Tuple[int, int], List[int]]]:
    cached = _LANE_BUCKETS_BY_STAGE.get(stage_idx)
    if cached is not None:
        return cached

    left: Dict[Tuple[int, int], List[int]] = defaultdict(list)
    right: Dict[Tuple[int, int], List[int]] = defaultdict(list)
    for word in range(0x10000):
        left[lane_word_signature_k0(word, stage_idx)].append(word)
        right[lane_word_signature_k1(word, stage_idx)].append(word)

    cached = dict(left), dict(right)
    _LANE_BUCKETS_BY_STAGE[stage_idx] = cached
    return cached


def lane_signatures_for_stage(stage_idx: int) -> List[Tuple[int, int, int, int]]:
    cached = _LANE_SIGNATURES_BY_STAGE.get(stage_idx)
    if cached is not None:
        return cached

    left_buckets, right_buckets = lane_buckets_for_stage(stage_idx)
    signatures = [
        (left_sig[0], left_sig[1], right_sig[0], right_sig[1])
        for left_sig in sorted(left_buckets)
        for right_sig in sorted(right_buckets)
    ]
    _LANE_SIGNATURES_BY_STAGE[stage_idx] = signatures
    return signatures


def signature_to_lane_betas(signature: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    return signature[0], signature[2], signature[1], signature[3]


def lane_perm_from_signature(signature: Tuple[int, int, int, int]) -> Tuple[int, ...]:
    beta0, beta1, beta2, beta3 = signature_to_lane_betas(signature)
    perm = []
    for b in range(16):
        v2 = S2[b ^ beta0]
        v3 = S2[v2 ^ beta1]
        v4 = S2[v3 ^ beta2]
        v5 = S2[v4 ^ beta3]
        out = S2[v5 ^ beta0 ^ beta1] ^ beta2 ^ beta3
        perm.append(out & 0xF)
    return tuple(perm)


def inverse_lane_perm(perm: Sequence[int]) -> Tuple[int, ...]:
    inverse = [0] * 16
    for idx, value in enumerate(perm):
        inverse[int(value) & 0xF] = idx & 0xF
    return tuple(inverse)


def inverse_lane_perms_for_stage(stage_idx: int) -> Dict[Tuple[int, int, int, int], Tuple[int, ...]]:
    cached = _INVERSE_LANE_PERMS_BY_STAGE.get(stage_idx)
    if cached is not None:
        return cached

    perms = {
        signature: inverse_lane_perm(lane_perm_from_signature(signature))
        for signature in lane_signatures_for_stage(stage_idx)
    }
    _INVERSE_LANE_PERMS_BY_STAGE[stage_idx] = perms
    return perms


def lane_class_candidates_for_signature(
    signature: Tuple[int, int, int, int],
    stage_idx: int,
    limit: Optional[int],
    seed: int,
) -> Tuple[List[Tuple[int, int]], int, bool]:
    left_buckets, right_buckets = lane_buckets_for_stage(stage_idx)
    left_words = left_buckets[(signature[0], signature[1])]
    right_words = right_buckets[(signature[2], signature[3])]
    total_size = len(left_words) * len(right_words)
    candidates = [(left_word, right_word) for left_word in left_words for right_word in right_words]
    if limit is None or limit <= 0 or limit >= total_size:
        return candidates, total_size, True

    rng = random.Random(seed)
    sampled = rng.sample(candidates, limit)
    canonical = (int(left_words[0]), int(right_words[0]))
    if canonical not in sampled:
        sampled[0] = canonical
    return sampled, total_size, False


def canonical_pair_for_signature(signature: Tuple[int, int, int, int], stage_idx: int) -> Tuple[int, int]:
    left_buckets, right_buckets = lane_buckets_for_stage(stage_idx)
    left_words = left_buckets[(signature[0], signature[1])]
    right_words = right_buckets[(signature[2], signature[3])]
    return int(left_words[0]), int(right_words[0])


def lane_class_candidates(
    true_pair: Tuple[int, int],
    stage_idx: int,
    class_limit: Optional[int],
    class_seed: int,
) -> Tuple[List[Tuple[int, int]], int, bool, Tuple[int, int, int, int]]:
    left_buckets, right_buckets = lane_buckets_for_stage(stage_idx)
    signature = lane_pair_signature(true_pair, stage_idx)
    left_words = left_buckets[(signature[0], signature[1])]
    right_words = right_buckets[(signature[2], signature[3])]

    total_size = len(left_words) * len(right_words)
    candidates = [(left_word, right_word) for left_word in left_words for right_word in right_words]

    if class_limit is None or class_limit <= 0 or class_limit >= len(candidates):
        return candidates, total_size, True, signature

    rng = random.Random(class_seed)
    sampled = rng.sample(candidates, class_limit)
    if true_pair not in sampled:
        sampled[0] = true_pair
    return sampled, total_size, False, signature


def reduced_right_inverse_table(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    target_stage: int,
) -> Dict[str, object]:
    ctx = ctx_after_prefix(key_words, iv_words, prefix_words)
    state = ctx["state"]
    assert isinstance(state, list)
    table = invert_table(next_word_table(ctx, key_words))

    for stage_idx in range(8, target_stage, -1):
        pair = stage_key_pair(key_words, stage_idx)
        state_word = state[stage_idx - 1]
        peeled = [0] * 0x10000
        for y in range(0x10000):
            peeled[y] = table[enc_block((y + state_word) & 0xFFFF, pair, stage_idx)]
        table = peeled

    return {
        "table": table,
        "state": list(state),
        "target_stage": target_stage,
    }


def build_true_inverse_reduced_tables(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
) -> Dict[str, object]:
    ctx = ctx_after_prefix(key_words, iv_words, prefix_words)
    state = ctx["state"]
    assert isinstance(state, list)
    current = invert_table(next_word_table(ctx, key_words))
    tables: List[Optional[List[int]]] = [None] * 10
    tables[1] = current
    for stage_idx in range(1, 9):
        pair = stage_key_pair(key_words, stage_idx)
        state_word = int(state[stage_idx - 1]) & 0xFFFF
        peeled = [0] * 0x10000
        for x in range(0x10000):
            peeled[x] = enc_block((int(current[x]) + state_word) & 0xFFFF, pair, stage_idx)
        current = peeled
        tables[stage_idx + 1] = current
    return {
        "tables": tables,
        "state": list(state),
    }


def extract_normalized_upper_map(table: Sequence[int], low: int) -> Optional[Tuple[int, ...]]:
    rows = [table[(row << 8):((row + 1) << 8)] for row in range(0x100)]
    observed: List[int] = []
    low &= 0xFF
    for row in rows:
        upper0 = ((int(row[0]) + low) & 0xFFFF) >> 8
        for value in row[1:]:
            if (((int(value) + low) & 0xFFFF) >> 8) != upper0:
                return None
        observed.append(upper0 & 0xFF)
    base = observed[0] & 0xFF
    return tuple(((value - base) & 0xFF) for value in observed)


def normalized_upper_map_from_pair(pair: Tuple[int, int], stage_idx: int) -> Tuple[int, ...]:
    observed = [((dec_block((row << 8) & 0xFFFF, pair, stage_idx) >> 8) & 0xFF) for row in range(0x100)]
    base = observed[0] & 0xFF
    return tuple(((value - base) & 0xFF) for value in observed)


def canonical_shift_tuple(values: Sequence[int], modulus: int) -> Tuple[int, ...]:
    unique = sorted({int(value) % modulus for value in values})
    if not unique:
        return ()
    best: Optional[Tuple[int, ...]] = None
    for base in unique:
        candidate = tuple(sorted(((value - base) % modulus) for value in unique))
        if best is None or candidate < best:
            best = candidate
    assert best is not None
    return best


def cyclic_distance(value_a: int, value_b: int, modulus: int) -> int:
    diff = (int(value_a) - int(value_b)) % modulus
    alt = (int(value_b) - int(value_a)) % modulus
    return min(diff, alt)


def support_profile(values: Sequence[int], modulus: int) -> Dict[str, object]:
    unique = sorted({int(value) % modulus for value in values})
    distances: List[int] = []
    for idx, lhs in enumerate(unique):
        for rhs in unique[idx + 1:]:
            distances.append(cyclic_distance(lhs, rhs, modulus))
    distances.sort()
    return {
        "support": tuple(unique),
        "size": len(unique),
        "distances": tuple(distances),
    }


def compute_raw_next_signature(table: Sequence[int]) -> Dict[str, object]:
    rows = [table[(row << 8):((row + 1) << 8)] for row in range(0x100)]
    upper_supports: List[Tuple[int, ...]] = []
    upper_canonical: List[Tuple[int, ...]] = []
    low_supports: List[Tuple[int, ...]] = []
    low_canonical: List[Tuple[int, ...]] = []
    for row in rows:
        support = tuple(sorted({(int(value) >> 8) & 0xFF for value in row}))
        upper_supports.append(support)
        upper_canonical.append(canonical_shift_tuple(support, 0x100))
        low_nibbles = tuple(sorted({value & 0x0F for value in support}))
        low_supports.append(low_nibbles)
        low_canonical.append(canonical_shift_tuple(low_nibbles, 0x10))
    upper_supports.sort()
    upper_canonical.sort()
    low_supports.sort()
    low_canonical.sort()
    return {
        "upper_support_multiset": upper_supports,
        "upper_canonical_multiset": upper_canonical,
        "low_nibble_support_multiset": low_supports,
        "low_nibble_canonical_multiset": low_canonical,
    }


def extract_upper_transport_signature(table: Sequence[int], low: int) -> Dict[str, object]:
    rows = [table[(row << 8):((row + 1) << 8)] for row in range(0x100)]
    upper_profiles = []
    low_profiles = []
    low &= 0xFF
    for row in rows:
        shifted = [((int(value) + low) & 0xFFFF) >> 8 for value in row]
        upper_profiles.append(support_profile(shifted, 0x100))
        low_profiles.append(support_profile([value & 0x0F for value in shifted], 0x10))
    upper_canonical = [canonical_shift_tuple(item["support"], 0x100) for item in upper_profiles]
    low_canonical = [canonical_shift_tuple(item["support"], 0x10) for item in low_profiles]
    return {
        "upper_support_multiset": sorted(item["support"] for item in upper_profiles),
        "upper_canonical_multiset": sorted(upper_canonical),
        "low_nibble_support_multiset": sorted(item["support"] for item in low_profiles),
        "low_nibble_canonical_multiset": sorted(low_canonical),
    }


def apply_upper_transport_signature(
    raw_next_signature: Dict[str, object],
    pair: Tuple[int, int],
    stage_idx: int,
    shift: int,
) -> Dict[str, object]:
    upper_map = [((dec_block((row << 8) & 0xFFFF, pair, stage_idx) >> 8) & 0xFF) for row in range(0x100)]
    shifted_supports: List[Tuple[int, ...]] = []
    shifted_canonical: List[Tuple[int, ...]] = []
    shifted_low_supports: List[Tuple[int, ...]] = []
    shifted_low_canonical: List[Tuple[int, ...]] = []
    supports = raw_next_signature["upper_support_multiset"]
    assert isinstance(supports, list)
    for support in supports:
        mapped = tuple(sorted({(upper_map[int(value) & 0xFF] + shift) & 0xFF for value in support}))
        shifted_supports.append(mapped)
        shifted_canonical.append(canonical_shift_tuple(mapped, 0x100))
        low_support = tuple(sorted({value & 0x0F for value in mapped}))
        shifted_low_supports.append(low_support)
        shifted_low_canonical.append(canonical_shift_tuple(low_support, 0x10))
    shifted_supports.sort()
    shifted_canonical.sort()
    shifted_low_supports.sort()
    shifted_low_canonical.sort()
    return {
        "upper_support_multiset": shifted_supports,
        "upper_canonical_multiset": shifted_canonical,
        "low_nibble_support_multiset": shifted_low_supports,
        "low_nibble_canonical_multiset": shifted_low_canonical,
    }


def validate_transport_law(
    key_words: Sequence[int],
    *,
    samples: int,
    seed: int,
    prefix_words: Sequence[int],
) -> List[Dict[str, object]]:
    rng = random.Random(seed)
    rows: List[Dict[str, object]] = []
    for trial in range(1, samples + 1):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        reduced = build_true_inverse_reduced_tables(key_words, iv_words, prefix_words)
        tables = reduced["tables"]
        state = reduced["state"]
        assert isinstance(tables, list)
        assert isinstance(state, list)
        stage_rows: Dict[int, Dict[str, object]] = {}
        for stage_idx in range(1, 8):
            table = tables[stage_idx]
            next_table = tables[stage_idx + 1]
            assert isinstance(table, list)
            assert isinstance(next_table, list)
            low = int(state[stage_idx - 1]) & 0xFF
            shift = (-((int(state[stage_idx - 1]) >> 8) & 0xFF)) & 0xFF
            observed = extract_upper_transport_signature(table, low)
            raw_next = compute_raw_next_signature(next_table)
            mapped = apply_upper_transport_signature(raw_next, stage_key_pair(key_words, stage_idx), stage_idx, shift)
            upper_match = observed["upper_support_multiset"] == mapped["upper_support_multiset"]
            canonical_match = observed["upper_canonical_multiset"] == mapped["upper_canonical_multiset"]
            stage_rows[stage_idx] = {
                "upper_match": upper_match,
                "canonical_match": canonical_match,
                "low": low,
                "shift": shift,
            }
        rows.append(
            {
                "trial": trial,
                "iv": words_to_hex(iv_words),
                "stages": stage_rows,
                "all_upper_match": all(bool(stage_rows[stage]["upper_match"]) for stage in stage_rows),
            }
        )
    return rows


def transport_pair_scan(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    target_stage: int,
    candidate_pairs: Sequence[Tuple[int, int]],
    *,
    topn: int,
) -> Dict[str, object]:
    if target_stage < 1 or target_stage > 7:
        raise ValueError("target_stage must be in 1..7 for transport-pair-scan")
    if not candidate_pairs:
        raise ValueError("candidate_pairs must be non-empty")

    reduced = build_true_inverse_reduced_tables(key_words, iv_words, prefix_words)
    tables = reduced["tables"]
    state = reduced["state"]
    assert isinstance(tables, list)
    assert isinstance(state, list)
    table = tables[target_stage]
    next_table = tables[target_stage + 1]
    assert isinstance(table, list)
    assert isinstance(next_table, list)

    true_pair = stage_key_pair(key_words, target_stage)
    true_state = int(state[target_stage - 1]) & 0xFFFF
    true_low = true_state & 0xFF
    true_high = (true_state >> 8) & 0xFF
    low_ranked = exact_low_byte_scan(table, topn=0x100)
    true_low_entry = next(item for item in low_ranked if int(item["low"]) == true_low)
    low_true_rank = 1 + sum(1 for item in low_ranked if int(item["total_support"]) < int(true_low_entry["total_support"]))
    observed = extract_upper_transport_signature(table, true_low)
    raw_next = compute_raw_next_signature(next_table)

    rows = []
    for pair in candidate_pairs:
        matching_shifts: List[int] = []
        canonical_shifts: List[int] = []
        for shift in range(0x100):
            mapped = apply_upper_transport_signature(raw_next, pair, target_stage, shift)
            if mapped["upper_canonical_multiset"] == observed["upper_canonical_multiset"]:
                canonical_shifts.append(shift)
            if mapped["upper_support_multiset"] == observed["upper_support_multiset"]:
                matching_shifts.append(shift)
        rows.append(
            {
                "pair": pair,
                "full_match": bool(matching_shifts),
                "match_count": len(matching_shifts),
                "canonical_count": len(canonical_shifts),
                "best_shift": matching_shifts[0] if matching_shifts else (canonical_shifts[0] if canonical_shifts else None),
            }
        )

    rows.sort(
        key=lambda item: (
            0 if bool(item["full_match"]) else 1,
            -int(item["match_count"]),
            -int(item["canonical_count"]),
            tuple(int(x) for x in item["pair"]),
        )
    )
    true_row = next(item for item in rows if tuple(item["pair"]) == true_pair)
    true_rank = 1 + sum(
        1
        for item in rows
        if tuple(item["pair"]) != true_pair
        and (
            0 if bool(item["full_match"]) else 1,
            -int(item["match_count"]),
            -int(item["canonical_count"]),
        )
        < (
            0 if bool(true_row["full_match"]) else 1,
            -int(true_row["match_count"]),
            -int(true_row["canonical_count"]),
        )
    )

    return {
        "iv": words_to_hex(iv_words),
        "target_stage": target_stage,
        "true_pair": true_pair,
        "true_state": true_state,
        "true_low": true_low,
        "true_high": true_high,
        "low_true_rank": low_true_rank,
        "true_rank": true_rank,
        "top_pairs": rows[: max(1, topn)],
    }


def peel_forward_right_stage_table(
    table: Sequence[int],
    pair: Tuple[int, int],
    stage_idx: int,
    state_word: int,
) -> List[int]:
    peeled = [0] * 0x10000
    state_word &= 0xFFFF
    for x in range(0x10000):
        peeled[x] = (dec_block(int(table[x]) & 0xFFFF, pair, stage_idx) - state_word) & 0xFFFF
    return peeled


def prepare_forward_right_stage_table(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    target_stage: int,
    known_outer_states: Dict[int, int],
) -> Dict[str, object]:
    if target_stage < 1 or target_stage > 8:
        raise ValueError("target_stage must be in 1..8")
    for stage_idx in range(8, target_stage, -1):
        if stage_idx not in known_outer_states:
            raise ValueError(f"known_outer_states must include stage {stage_idx}")

    ctx = ctx_after_prefix(key_words, iv_words, prefix_words)
    table = next_word_table(ctx, key_words)
    for stage_idx in range(8, target_stage, -1):
        table = peel_forward_right_stage_table(
            table,
            stage_key_pair(key_words, stage_idx),
            stage_idx,
            int(known_outer_states[stage_idx]) & 0xFFFF,
        )
    return {
        "table": table,
        "state": list(ctx["state"]),  # type: ignore[arg-type]
        "target_stage": target_stage,
    }


def build_stage1_codebook_from_context(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    k2_pair: Tuple[int, int],
    known_outer_states: Dict[int, int],
) -> Dict[str, object]:
    for stage_idx in range(2, 9):
        if stage_idx not in known_outer_states:
            raise ValueError(f"known_outer_states must include stage {stage_idx} for stage-1 codebook recovery")

    prepared = prepare_forward_right_stage_table(
        key_words,
        iv_words,
        prefix_words,
        2,
        {stage: int(known_outer_states[stage]) & 0xFFFF for stage in range(3, 9)},
    )
    source_table = prepared["table"]
    assert isinstance(source_table, list)
    state_words = prepared["state"]
    assert isinstance(state_words, list)
    codebook = peel_forward_right_stage_table(source_table, k2_pair, 2, int(known_outer_states[2]) & 0xFFFF)
    return {
        "codebook": codebook,
        "true_state": int(state_words[0]) & 0xFFFF,
        "true_k1": stage_key_pair(key_words, 1),
        "true_k2": stage_key_pair(key_words, 2),
    }


def peel_current_forward_stage_table(
    source_table: Sequence[int],
    pair: Tuple[int, int],
    stage_idx: int,
) -> List[int]:
    peeled = [0] * 0x10000
    for x in range(0x10000):
        peeled[x] = dec_block(int(source_table[x]) & 0xFFFF, pair, stage_idx)
    return peeled


def subtract_translation(table: Sequence[int], translation: int) -> List[int]:
    translation &= 0xFFFF
    return [((int(value) - translation) & 0xFFFF) for value in table]


def row_support_for_low(peeled_table: Sequence[int], low_byte: int) -> Tuple[int, Tuple[int, int, int, int]]:
    low_byte &= 0xFF
    total_support = 0
    sample_rows = []
    watched_rows = (0x00, 0x55, 0xAA, 0xFF)
    for row in range(0x100):
        base = row << 8
        uppers = set()
        for lo in range(0x100):
            upper = ((int(peeled_table[base | lo]) - low_byte) & 0xFFFF) >> 8
            uppers.add(upper)
        count = len(uppers)
        total_support += count
        if row in watched_rows:
            sample_rows.append(count)
    return total_support, tuple(sample_rows)  # type: ignore[return-value]


def exact_low_byte_scan(
    peeled_table: Sequence[int],
    *,
    topn: int,
) -> List[Dict[str, object]]:
    ranked = []
    for low_byte in range(0x100):
        total_support, sample_rows = row_support_for_low(peeled_table, low_byte)
        ranked.append(
            {
                "low": low_byte,
                "total_support": total_support,
                "sample_rows": sample_rows,
            }
        )
    ranked.sort(key=lambda item: (int(item["total_support"]), int(item["low"])))
    return ranked[: max(1, topn)]


def rank_high_support_candidates(
    source_table: Sequence[int],
    next_pair: Tuple[int, int],
    stage_idx: int,
    *,
    row_step: int,
) -> List[Dict[str, object]]:
    if row_step <= 0:
        raise ValueError("row_step must be positive")

    ranked = []
    row_values = [0] * 0x100
    seen = [0] * 0x100
    watched_rows = (0x00, 0x40, 0x80, 0xC0)

    for high in range(0x100):
        total_support = 0
        sample_rows = []
        high_translation = (high & 0xFF) << 8
        for row in range(0, 0x100, row_step):
            base = row << 8
            for lo in range(0x100):
                row_values[lo] = dec_block((int(source_table[base | lo]) - high_translation) & 0xFFFF, next_pair, stage_idx)

            best_support = 0x101
            best_low = 0
            for low in range(0x100):
                mark = low + 1
                count = 0
                for lo in range(0x100):
                    upper = ((row_values[lo] - low) & 0xFFFF) >> 8
                    if seen[upper] != mark:
                        seen[upper] = mark
                        count += 1
                        if count >= best_support:
                            break
                if count < best_support:
                    best_support = count
                    best_low = low
                    if best_support == 1:
                        break

            total_support += best_support
            if row in watched_rows:
                sample_rows.append((row, best_support, best_low))

        ranked.append(
            {
                "high": high,
                "score": total_support,
                "sample_rows": tuple(sample_rows),
            }
        )

    ranked.sort(key=lambda item: (int(item["score"]), int(item["high"])))
    return ranked


def constancy_score_stage1(source_table: Sequence[int], translation: int, pair: Tuple[int, int]) -> Tuple[int, int]:
    counts = [0] * 0x10000
    touched: List[int] = []
    best_score = 0
    best_delta = 0

    translation &= 0xFFFF
    for x in range(0x10000):
        delta = (dec_block((int(source_table[x]) - translation) & 0xFFFF, pair, 1) - x) & 0xFFFF
        counts[delta] += 1
        if counts[delta] == 1:
            touched.append(delta)
        if counts[delta] > best_score or (counts[delta] == best_score and delta < best_delta):
            best_score = counts[delta]
            best_delta = delta

    for delta in touched:
        counts[delta] = 0
    return best_score, best_delta


def rank_high_constancy_candidates_stage1(source_table: Sequence[int], low_byte: int, next_pair: Tuple[int, int]) -> List[Dict[str, object]]:
    ranked = []
    low_byte &= 0xFF
    for high in range(0x100):
        translation = low_byte | (high << 8)
        score, best_delta = constancy_score_stage1(source_table, translation, next_pair)
        ranked.append(
            {
                "high": high,
                "score": score,
                "best_delta": best_delta,
            }
        )
    ranked.sort(key=lambda item: (-int(item["score"]), int(item["high"])))
    return ranked


def exact_stage_high_byte_scan(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    target_stage: int,
    candidate_pair: Tuple[int, int],
    known_outer_states: Dict[int, int],
    candidate_next_pairs: Sequence[Tuple[int, int]],
    *,
    fixed_low: Optional[int],
    row_step: int,
    topn: int,
) -> Dict[str, object]:
    if target_stage <= 1 or target_stage > 8:
        raise ValueError("target_stage must be in 2..8")
    if not candidate_next_pairs:
        raise ValueError("candidate_next_pairs must be non-empty")

    prepared = prepare_forward_right_stage_table(
        key_words,
        iv_words,
        prefix_words,
        target_stage,
        known_outer_states,
    )
    source_table = prepared["table"]
    assert isinstance(source_table, list)
    work_table = peel_current_forward_stage_table(source_table, candidate_pair, target_stage)
    state_words = prepared["state"]
    assert isinstance(state_words, list)
    true_state = int(state_words[target_stage - 1]) & 0xFFFF
    true_low = true_state & 0xFF
    true_high = (true_state >> 8) & 0xFF

    low_ranked = exact_low_byte_scan(work_table, topn=0x100)
    low_winner = int(low_ranked[0]["low"]) if fixed_low is None else (fixed_low & 0xFF)
    low_true_rank = 1 + sum(1 for item in low_ranked if int(item["total_support"]) < next(int(x["total_support"]) for x in low_ranked if int(x["low"]) == true_low))

    aligned_low = subtract_translation(work_table, low_winner)
    true_next_pair = stage_key_pair(key_words, target_stage - 1)

    if len(candidate_next_pairs) == 1:
        next_pair = candidate_next_pairs[0]
        if target_stage == 2:
            ranked = rank_high_constancy_candidates_stage1(work_table, low_winner, next_pair)
            true_entry = next(item for item in ranked if int(item["high"]) == true_high)
            true_rank = 1 + sum(1 for item in ranked if int(item["score"]) > int(true_entry["score"]))
        else:
            ranked = rank_high_support_candidates(aligned_low, next_pair, target_stage - 1, row_step=row_step)
            true_entry = next(item for item in ranked if int(item["high"]) == true_high)
            true_rank = 1 + sum(1 for item in ranked if int(item["score"]) < int(true_entry["score"]))
        return {
            "iv": words_to_hex(iv_words),
            "target_stage": target_stage,
            "candidate_pair": candidate_pair,
            "candidate_next_pair": next_pair,
            "true_state": true_state,
            "true_low": true_low,
            "used_low": low_winner,
            "low_true_rank": low_true_rank,
            "true_high": true_high,
            "true_high_rank": true_rank,
            "true_next_pair": true_next_pair,
            "top_highs": ranked[: max(1, topn)],
            "score_kind": "constancy" if target_stage == 2 else "support",
            "row_step": row_step,
        }

    pair_ranked = []
    for next_pair in candidate_next_pairs:
        if target_stage == 2:
            ranked = rank_high_constancy_candidates_stage1(work_table, low_winner, next_pair)
            best = ranked[0]
            pair_ranked.append(
                {
                    "pair": next_pair,
                    "score": int(best["score"]),
                    "best_high": int(best["high"]),
                    "best_delta": int(best["best_delta"]),
                }
            )
        else:
            ranked = rank_high_support_candidates(aligned_low, next_pair, target_stage - 1, row_step=row_step)
            best = ranked[0]
            pair_ranked.append(
                {
                    "pair": next_pair,
                    "score": int(best["score"]),
                    "best_high": int(best["high"]),
                    "sample_rows": best["sample_rows"],
                }
            )

    if target_stage == 2:
        pair_ranked.sort(key=lambda item: (-int(item["score"]), tuple(int(x) for x in item["pair"])))
        true_pair_entry = next(item for item in pair_ranked if tuple(item["pair"]) == true_next_pair)
        true_pair_rank = 1 + sum(1 for item in pair_ranked if int(item["score"]) > int(true_pair_entry["score"]))
    else:
        pair_ranked.sort(key=lambda item: (int(item["score"]), tuple(int(x) for x in item["pair"])))
        true_pair_entry = next(item for item in pair_ranked if tuple(item["pair"]) == true_next_pair)
        true_pair_rank = 1 + sum(1 for item in pair_ranked if int(item["score"]) < int(true_pair_entry["score"]))

    return {
        "iv": words_to_hex(iv_words),
        "target_stage": target_stage,
        "candidate_pair": candidate_pair,
        "true_state": true_state,
        "true_low": true_low,
        "used_low": low_winner,
        "low_true_rank": low_true_rank,
        "true_high": true_high,
        "true_next_pair": true_next_pair,
        "true_pair_rank": true_pair_rank,
        "top_pairs": pair_ranked[: max(1, topn)],
        "score_kind": "constancy" if target_stage == 2 else "support",
        "row_step": row_step,
    }


def recursive_pair_scan(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    target_stage: int,
    candidate_pair: Tuple[int, int],
    known_outer_states: Dict[int, int],
    candidate_next_pairs: Sequence[Tuple[int, int]],
    *,
    fixed_low: Optional[int],
    row_step: int,
    topn: int,
) -> Dict[str, object]:
    if target_stage <= 2 or target_stage > 8:
        raise ValueError("target_stage must be in 3..8 for recursive-pair-scan")
    if not candidate_next_pairs:
        raise ValueError("candidate_next_pairs must be non-empty")

    prepared = prepare_forward_right_stage_table(
        key_words,
        iv_words,
        prefix_words,
        target_stage,
        known_outer_states,
    )
    source_table = prepared["table"]
    assert isinstance(source_table, list)
    work_table = peel_current_forward_stage_table(source_table, candidate_pair, target_stage)
    state_words = prepared["state"]
    assert isinstance(state_words, list)
    true_state = int(state_words[target_stage - 1]) & 0xFFFF
    true_low = true_state & 0xFF
    true_high = (true_state >> 8) & 0xFF
    true_next_pair = stage_key_pair(key_words, target_stage - 1)
    true_next_low = int(state_words[target_stage - 2]) & 0xFF

    low_ranked = exact_low_byte_scan(work_table, topn=0x100)
    true_low_entry = next(item for item in low_ranked if int(item["low"]) == true_low)
    low_true_rank = 1 + sum(1 for item in low_ranked if int(item["total_support"]) < int(true_low_entry["total_support"]))
    low_winner = int(low_ranked[0]["low"]) if fixed_low is None else (fixed_low & 0xFF)

    aligned_low = subtract_translation(work_table, low_winner)
    pair_rows = []
    for next_pair in candidate_next_pairs:
        high_ranked = rank_high_support_candidates(aligned_low, next_pair, target_stage - 1, row_step=row_step)
        best_high_entry = high_ranked[0]
        best_high = int(best_high_entry["high"]) & 0xFF
        best_high_score = int(best_high_entry["score"])
        guessed_state = low_winner | (best_high << 8)

        next_source = subtract_translation(work_table, guessed_state)
        next_work = peel_current_forward_stage_table(next_source, next_pair, target_stage - 1)
        next_low_ranked = exact_low_byte_scan(next_work, topn=0x100)
        next_best = next_low_ranked[0]
        next_second = next_low_ranked[1] if len(next_low_ranked) > 1 else next_best
        true_next_entry = next(item for item in next_low_ranked if int(item["low"]) == true_next_low)
        true_next_low_rank = 1 + sum(
            1 for item in next_low_ranked if int(item["total_support"]) < int(true_next_entry["total_support"])
        )
        pair_rows.append(
            {
                "pair": next_pair,
                "best_high": best_high,
                "high_score": best_high_score,
                "next_low": int(next_best["low"]),
                "next_low_score": int(next_best["total_support"]),
                "next_low_gap": int(next_second["total_support"]) - int(next_best["total_support"]),
                "true_next_low_rank": true_next_low_rank if next_pair == true_next_pair else None,
            }
        )

    pair_rows.sort(key=lambda item: (int(item["high_score"]), -int(item["next_low_gap"]), int(item["next_low_score"]), tuple(int(x) for x in item["pair"])))
    true_pair_entry = next(item for item in pair_rows if tuple(item["pair"]) == true_next_pair)
    true_pair_rank = 1 + sum(
        1
        for item in pair_rows
        if tuple(item["pair"]) != true_next_pair
        and (
            int(item["high_score"]),
            -int(item["next_low_gap"]),
            int(item["next_low_score"]),
        )
        < (
            int(true_pair_entry["high_score"]),
            -int(true_pair_entry["next_low_gap"]),
            int(true_pair_entry["next_low_score"]),
        )
    )

    return {
        "iv": words_to_hex(iv_words),
        "target_stage": target_stage,
        "candidate_pair": candidate_pair,
        "true_state": true_state,
        "true_low": true_low,
        "true_high": true_high,
        "used_low": low_winner,
        "low_true_rank": low_true_rank,
        "true_next_pair": true_next_pair,
        "true_next_low": true_next_low,
        "true_pair_rank": true_pair_rank,
        "top_pairs": pair_rows[: max(1, topn)],
    }


def exact_stage_low_byte_scan(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    target_stage: int,
    candidate_pair: Tuple[int, int],
    known_outer_states: Dict[int, int],
    *,
    topn: int,
) -> Dict[str, object]:
    prepared = prepare_forward_right_stage_table(
        key_words,
        iv_words,
        prefix_words,
        target_stage,
        known_outer_states,
    )
    source_table = prepared["table"]
    assert isinstance(source_table, list)
    peeled_table = peel_current_forward_stage_table(source_table, candidate_pair, target_stage)
    state_words = prepared["state"]
    assert isinstance(state_words, list)
    true_state = int(state_words[target_stage - 1]) & 0xFFFF
    true_low = true_state & 0xFF

    ranked = exact_low_byte_scan(peeled_table, topn=max(256, topn))
    true_entry = next(item for item in ranked if int(item["low"]) == true_low)
    true_rank = 1 + sum(1 for item in ranked if int(item["total_support"]) < int(true_entry["total_support"]))

    return {
        "iv": words_to_hex(iv_words),
        "target_stage": target_stage,
        "candidate_pair": candidate_pair,
        "true_state": true_state,
        "true_low": true_low,
        "true_rank": true_rank,
        "true_total_support": int(true_entry["total_support"]),
        "top": ranked[: max(1, topn)],
    }


def row_best_support_after_peel(
    source_table: Sequence[int],
    pair: Tuple[int, int],
    stage_idx: int,
    row: int,
) -> Tuple[int, int]:
    row &= 0xFF
    base = row << 8
    peeled = [dec_block(int(source_table[base | lo]) & 0xFFFF, pair, stage_idx) for lo in range(0x100)]

    best_support = 0x100
    best_low = 0
    for low_byte in range(0x100):
        support = len({(((value - low_byte) & 0xFFFF) >> 8) for value in peeled})
        if support < best_support or (support == best_support and low_byte < best_low):
            best_support = support
            best_low = low_byte
    return best_support, best_low


def support_collapse_score_after_peel(
    source_table: Sequence[int],
    pair: Tuple[int, int],
    stage_idx: int,
    rows: Sequence[int],
) -> Tuple[int, List[Tuple[int, int, int]]]:
    total = 0
    details = []
    for row in rows:
        support, low = row_best_support_after_peel(source_table, pair, stage_idx, row)
        total += support
        details.append((int(row) & 0xFF, support, low))
    return total, details


def exact_stage_support_collapse_scan(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    target_stage: int,
    known_outer_states: Dict[int, int],
    candidate_pairs: Sequence[Tuple[int, int]],
    *,
    rows: Sequence[int],
    topn: int,
) -> Dict[str, object]:
    if target_stage < 1 or target_stage > 8:
        raise ValueError("target_stage must be in 1..8")
    if not candidate_pairs:
        raise ValueError("candidate_pairs must be non-empty")

    prepared = prepare_forward_right_stage_table(
        key_words,
        iv_words,
        prefix_words,
        target_stage,
        known_outer_states,
    )
    source_table = prepared["table"]
    assert isinstance(source_table, list)
    state_words = prepared["state"]
    assert isinstance(state_words, list)

    true_pair = stage_key_pair(key_words, target_stage)
    true_state = int(state_words[target_stage - 1]) & 0xFFFF

    ranked = []
    for pair in candidate_pairs:
        total, details = support_collapse_score_after_peel(source_table, pair, target_stage, rows)
        ranked.append((total, pair, details))
    ranked.sort(key=lambda item: (int(item[0]), tuple(int(x) for x in item[1])))

    true_row = next(item for item in ranked if tuple(item[1]) == true_pair)
    true_rank = 1 + sum(1 for item in ranked if tuple(item[1]) != true_pair and int(item[0]) < int(true_row[0]))
    true_ties = sum(1 for item in ranked if int(item[0]) == int(true_row[0]))

    return {
        "iv": words_to_hex(iv_words),
        "target_stage": target_stage,
        "true_pair": true_pair,
        "true_state": true_state,
        "rows": [int(row) & 0xFF for row in rows],
        "true_rank": true_rank,
        "true_ties": true_ties,
        "true_score": int(true_row[0]),
        "top_pairs": ranked[: max(1, topn)],
    }


def stage1_finish_scan(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    k2_pair: Tuple[int, int],
    known_outer_states: Dict[int, int],
) -> Dict[str, object]:
    built = build_stage1_codebook_from_context(key_words, iv_words, prefix_words, k2_pair, known_outer_states)
    codebook = built["codebook"]
    assert isinstance(codebook, list)
    recovered = recover_stage_local(1, codebook)
    true_k1 = built["true_k1"]
    assert isinstance(true_k1, tuple)
    true_s1 = int(built["true_state"]) & 0xFFFF
    true_rank = None
    for idx, item in enumerate(recovered, start=1):
        if (int(item["k0"]), int(item["k1"])) == true_k1 and int(item["state_word"]) == true_s1:
            true_rank = idx
            break
    return {
        "iv": words_to_hex(iv_words),
        "prefix": list(prefix_words),
        "k2_pair": (int(k2_pair[0]) & 0xFFFF, int(k2_pair[1]) & 0xFFFF),
        "true_k1": true_k1,
        "true_s1": true_s1,
        "true_rank": true_rank,
        "recovered": recovered,
    }


def sampled_injected_right_score(
    oracle_table: Sequence[int],
    stage_idx: int,
    pair: Tuple[int, int],
    diffs: Sequence[int],
    sample_x: Sequence[int],
) -> Tuple[int, List[Tuple[int, int, int, int]]]:
    total = 0
    per_diff = []
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in sample_x:
            left = oracle_table[enc_block((x + diff) & 0xFFFF, pair, stage_idx)]
            right = oracle_table[enc_block(x, pair, stage_idx)]
            out_diff = (int(left) - int(right)) & 0xFFFF
            counts[out_diff] = counts.get(out_diff, 0) + 1
        best_out, best_count = max(counts.items(), key=lambda item: (item[1], -item[0]))
        total += best_count
        per_diff.append((diff & 0xFFFF, best_out & 0xFFFF, best_count, len(counts)))
    return total, per_diff


def exact_injected_right_score(
    oracle_table: Sequence[int],
    stage_idx: int,
    pair: Tuple[int, int],
    diffs: Sequence[int],
) -> Tuple[int, List[Tuple[int, int, int, int]]]:
    total = 0
    per_diff = []
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in range(0x10000):
            left = oracle_table[enc_block((x + diff) & 0xFFFF, pair, stage_idx)]
            right = oracle_table[enc_block(x, pair, stage_idx)]
            out_diff = (int(left) - int(right)) & 0xFFFF
            counts[out_diff] = counts.get(out_diff, 0) + 1
        best_out, best_count = max(counts.items(), key=lambda item: (item[1], -item[0]))
        total += best_count
        per_diff.append((diff & 0xFFFF, best_out & 0xFFFF, best_count, len(counts)))
    return total, per_diff


def apply_public_right_guesses(
    public_inverse_table: Sequence[int],
    key_words: Sequence[int],
    word: int,
    guessed_states: Dict[int, int],
) -> int:
    value = word & 0xFFFF
    for stage_idx in sorted(guessed_states):
        value = enc_block((value + int(guessed_states[stage_idx])) & 0xFFFF, stage_key_pair(key_words, stage_idx), stage_idx)
    return int(public_inverse_table[value]) & 0xFFFF


def sampled_public_right_state_score(
    public_inverse_table: Sequence[int],
    key_words: Sequence[int],
    guessed_states: Dict[int, int],
    next_stage: int,
    diffs: Sequence[int],
    sample_x: Sequence[int],
) -> Tuple[int, List[Tuple[int, int, int, int]]]:
    pair = stage_key_pair(key_words, next_stage)
    total = 0
    per_diff = []
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in sample_x:
            a = enc_block((x + diff) & 0xFFFF, pair, next_stage)
            b = enc_block(x, pair, next_stage)
            left = apply_public_right_guesses(public_inverse_table, key_words, a, guessed_states)
            right = apply_public_right_guesses(public_inverse_table, key_words, b, guessed_states)
            out_diff = (left - right) & 0xFFFF
            counts[out_diff] = counts.get(out_diff, 0) + 1
        best_out, best_count = max(counts.items(), key=lambda item: (item[1], -item[0]))
        total += best_count
        per_diff.append((diff & 0xFFFF, best_out & 0xFFFF, best_count, len(counts)))
    return total, per_diff


def exact_public_right_state_score(
    public_inverse_table: Sequence[int],
    key_words: Sequence[int],
    guessed_states: Dict[int, int],
    next_stage: int,
    diffs: Sequence[int],
) -> Tuple[int, List[Tuple[int, int, int, int]]]:
    pair = stage_key_pair(key_words, next_stage)
    total = 0
    per_diff = []
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in range(0x10000):
            a = enc_block((x + diff) & 0xFFFF, pair, next_stage)
            b = enc_block(x, pair, next_stage)
            left = apply_public_right_guesses(public_inverse_table, key_words, a, guessed_states)
            right = apply_public_right_guesses(public_inverse_table, key_words, b, guessed_states)
            out_diff = (left - right) & 0xFFFF
            counts[out_diff] = counts.get(out_diff, 0) + 1
        best_out, best_count = max(counts.items(), key=lambda item: (item[1], -item[0]))
        total += best_count
        per_diff.append((diff & 0xFFFF, best_out & 0xFFFF, best_count, len(counts)))
    return total, per_diff


def public_right_state_byte_scan(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    scan_stage: int,
    outer_state_guesses: Dict[int, int],
    *,
    part: str,
    fixed_other_byte: int,
    diffs: Sequence[int],
    sample_x: Sequence[int],
    exact_top: int,
) -> Dict[str, object]:
    if scan_stage <= 1 or scan_stage > 8:
        raise ValueError("scan_stage must be in 2..8 so that a next visible inner stage exists")
    for stage_idx in outer_state_guesses:
        if stage_idx <= scan_stage:
            raise ValueError("known right-state guesses must only include stages strictly outside the scanned stage")

    ctx = ctx_after_prefix(key_words, iv_words, prefix_words)
    public_inverse_table = invert_table(next_word_table(ctx, key_words))
    state_words = ctx["state"]
    assert isinstance(state_words, list)
    true_state = int(state_words[scan_stage - 1]) & 0xFFFF

    sampled = []
    for candidate_byte in range(0x100):
        if part == "low":
            guess_word = ((fixed_other_byte & 0xFF) << 8) | candidate_byte
        else:
            guess_word = ((candidate_byte & 0xFF) << 8) | (fixed_other_byte & 0xFF)
        guessed_states = dict(outer_state_guesses)
        guessed_states[scan_stage] = guess_word
        score, per_diff = sampled_public_right_state_score(
            public_inverse_table,
            key_words,
            guessed_states,
            scan_stage - 1,
            diffs,
            sample_x,
        )
        sampled.append((score, candidate_byte, guess_word, per_diff))
    sampled.sort(key=lambda item: (-item[0], item[1]))

    true_byte = (true_state & 0xFF) if part == "low" else ((true_state >> 8) & 0xFF)
    true_sampled_score = next(score for score, byte, _, _ in sampled if byte == true_byte)
    true_sampled_rank = 1 + sum(1 for score, byte, _, _ in sampled if byte != true_byte and score > true_sampled_score)

    exact = []
    if exact_top > 0:
        shortlisted = [byte for _, byte, _, _ in sampled[:exact_top]]
        if true_byte not in shortlisted:
            shortlisted.append(true_byte)
        for candidate_byte in shortlisted:
            if part == "low":
                guess_word = ((fixed_other_byte & 0xFF) << 8) | candidate_byte
            else:
                guess_word = ((candidate_byte & 0xFF) << 8) | (fixed_other_byte & 0xFF)
            guessed_states = dict(outer_state_guesses)
            guessed_states[scan_stage] = guess_word
            score, per_diff = exact_public_right_state_score(
                public_inverse_table,
                key_words,
                guessed_states,
                scan_stage - 1,
                diffs,
            )
            exact.append((score, candidate_byte, guess_word, per_diff))
        exact.sort(key=lambda item: (-item[0], item[1]))

    exact_true_rank = None
    exact_true_score = None
    if exact:
        exact_true_score = next(score for score, byte, _, _ in exact if byte == true_byte)
        exact_true_rank = 1 + sum(1 for score, byte, _, _ in exact if byte != true_byte and score > exact_true_score)

    return {
        "iv": words_to_hex(iv_words),
        "scan_stage": scan_stage,
        "next_stage": scan_stage - 1,
        "part": part,
        "true_state": true_state,
        "true_byte": true_byte,
        "fixed_other_byte": fixed_other_byte & 0xFF,
        "sampled_true_rank": true_sampled_rank,
        "sampled_true_score": true_sampled_score,
        "sampled_top": sampled[: min(8, len(sampled))],
        "exact_true_rank": exact_true_rank,
        "exact_true_score": exact_true_score,
        "exact_top": exact[: min(8, len(exact))],
    }


def sampled_outer_s8_score(
    public_inverse_table: Sequence[int],
    k7_pair: Tuple[int, int],
    k8_pair: Tuple[int, int],
    guessed_s8: int,
    diffs: Sequence[int],
    sample_x: Sequence[int],
) -> Tuple[int, List[Tuple[int, int, int, int]]]:
    total = 0
    per_diff = []
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in sample_x:
            left_input = enc_block((x + diff) & 0xFFFF, k7_pair, 7)
            right_input = enc_block(x, k7_pair, 7)
            left = int(public_inverse_table[enc_block((left_input + guessed_s8) & 0xFFFF, k8_pair, 8)]) & 0xFFFF
            right = int(public_inverse_table[enc_block((right_input + guessed_s8) & 0xFFFF, k8_pair, 8)]) & 0xFFFF
            out_diff = (left - right) & 0xFFFF
            counts[out_diff] = counts.get(out_diff, 0) + 1
        best_out, best_count = max(counts.items(), key=lambda item: (item[1], -item[0]))
        total += best_count
        per_diff.append((diff & 0xFFFF, best_out & 0xFFFF, best_count, len(counts)))
    return total, per_diff


def exact_outer_s8_score(
    public_inverse_table: Sequence[int],
    k7_pair: Tuple[int, int],
    k8_pair: Tuple[int, int],
    guessed_s8: int,
    diffs: Sequence[int],
) -> Tuple[int, List[Tuple[int, int, int, int]]]:
    total = 0
    per_diff = []
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in range(0x10000):
            left_input = enc_block((x + diff) & 0xFFFF, k7_pair, 7)
            right_input = enc_block(x, k7_pair, 7)
            left = int(public_inverse_table[enc_block((left_input + guessed_s8) & 0xFFFF, k8_pair, 8)]) & 0xFFFF
            right = int(public_inverse_table[enc_block((right_input + guessed_s8) & 0xFFFF, k8_pair, 8)]) & 0xFFFF
            out_diff = (left - right) & 0xFFFF
            counts[out_diff] = counts.get(out_diff, 0) + 1
        best_out, best_count = max(counts.items(), key=lambda item: (item[1], -item[0]))
        total += best_count
        per_diff.append((diff & 0xFFFF, best_out & 0xFFFF, best_count, len(counts)))
    return total, per_diff


def outer_s8_word_scan(
    oracle_key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    k7_pair: Tuple[int, int],
    *,
    diffs: Sequence[int],
    sample_x: Sequence[int],
    sampled_top: int,
    exact_top: int,
) -> Dict[str, object]:
    ctx = ctx_after_prefix(oracle_key_words, iv_words, prefix_words)
    public_inverse_table = invert_table(next_word_table(ctx, oracle_key_words))
    state_words = ctx["state"]
    assert isinstance(state_words, list)
    true_state = int(state_words[7]) & 0xFFFF
    k8_pair = stage_key_pair(oracle_key_words, 8)

    heap: List[Tuple[int, int]] = []
    true_sampled_score = None
    for guessed_s8 in range(0x10000):
        score, _ = sampled_outer_s8_score(public_inverse_table, k7_pair, k8_pair, guessed_s8, diffs, sample_x)
        if guessed_s8 == true_state:
            true_sampled_score = score
        if sampled_top > 0:
            if len(heap) < sampled_top:
                heapq.heappush(heap, (score, guessed_s8))
            elif score > heap[0][0]:
                heapq.heapreplace(heap, (score, guessed_s8))

    if true_sampled_score is None:
        raise AssertionError("true outer state score missing")

    sampled_shortlist = sorted(heap, reverse=True)
    sampled_true_rank = 1 + sum(1 for score, _ in sampled_shortlist if score > true_sampled_score)
    shortlisted_words = [candidate_word for _, candidate_word in sampled_shortlist]
    if true_state not in shortlisted_words:
        shortlisted_words.append(true_state)

    exact = []
    for guessed_s8 in shortlisted_words[: max(0, exact_top)] if exact_top > 0 else []:
        score, per_diff = exact_outer_s8_score(public_inverse_table, k7_pair, k8_pair, guessed_s8, diffs)
        exact.append((score, guessed_s8, per_diff))
    if exact_top > 0 and true_state not in [word for _, word, _ in exact]:
        score, per_diff = exact_outer_s8_score(public_inverse_table, k7_pair, k8_pair, true_state, diffs)
        exact.append((score, true_state, per_diff))

    exact.sort(key=lambda item: (-item[0], item[1]))
    exact_true_score = None
    exact_true_rank = None
    if exact:
        exact_true_score = next(score for score, word, _ in exact if word == true_state)
        exact_true_rank = 1 + sum(1 for score, word, _ in exact if word != true_state and score > exact_true_score)

    return {
        "iv": words_to_hex(iv_words),
        "scan_stage": 8,
        "next_stage": 7,
        "true_state": true_state,
        "candidate_pair": k7_pair,
        "sampled_true_score": true_sampled_score,
        "sampled_true_rank": sampled_true_rank,
        "sampled_top": sampled_shortlist[: min(8, len(sampled_shortlist))],
        "exact_true_score": exact_true_score,
        "exact_true_rank": exact_true_rank,
        "exact_top": exact[: min(8, len(exact))],
    }


def public_right_state_word_scan(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    scan_stage: int,
    outer_state_guesses: Dict[int, int],
    *,
    oracle_key_words: Optional[Sequence[int]] = None,
    diffs: Sequence[int],
    sample_x: Sequence[int],
    sampled_top: int,
    exact_top: int,
) -> Dict[str, object]:
    if scan_stage <= 1 or scan_stage > 8:
        raise ValueError("scan_stage must be in 2..8 so that a next visible inner stage exists")
    for stage_idx in outer_state_guesses:
        if stage_idx <= scan_stage:
            raise ValueError("known right-state guesses must only include stages strictly outside the scanned stage")

    oracle_key = key_words if oracle_key_words is None else oracle_key_words
    ctx = ctx_after_prefix(oracle_key, iv_words, prefix_words)
    public_inverse_table = invert_table(next_word_table(ctx, oracle_key))
    state_words = ctx["state"]
    assert isinstance(state_words, list)
    true_state = int(state_words[scan_stage - 1]) & 0xFFFF

    heap: List[Tuple[int, int]] = []
    true_sampled_score = None
    for candidate_word in range(0x10000):
        guessed_states = dict(outer_state_guesses)
        guessed_states[scan_stage] = candidate_word
        score, _ = sampled_public_right_state_score(
            public_inverse_table,
            key_words,
            guessed_states,
            scan_stage - 1,
            diffs,
            sample_x,
        )
        if candidate_word == true_state:
            true_sampled_score = score
        if sampled_top > 0:
            if len(heap) < sampled_top:
                heapq.heappush(heap, (score, candidate_word))
            elif score > heap[0][0]:
                heapq.heapreplace(heap, (score, candidate_word))

    if true_sampled_score is None:
        raise AssertionError("true state score missing")

    sampled_shortlist = sorted(heap, reverse=True)
    sampled_true_rank = 1 + sum(1 for score, _ in sampled_shortlist if score > true_sampled_score)
    shortlisted_words = [candidate_word for _, candidate_word in sampled_shortlist]
    if true_state not in shortlisted_words:
        shortlisted_words.append(true_state)

    exact = []
    for candidate_word in shortlisted_words[: max(0, exact_top)] if exact_top > 0 else []:
        guessed_states = dict(outer_state_guesses)
        guessed_states[scan_stage] = candidate_word
        score, per_diff = exact_public_right_state_score(
            public_inverse_table,
            key_words,
            guessed_states,
            scan_stage - 1,
            diffs,
        )
        exact.append((score, candidate_word, per_diff))

    if exact_top > 0 and true_state not in [word for _, word, _ in exact]:
        guessed_states = dict(outer_state_guesses)
        guessed_states[scan_stage] = true_state
        score, per_diff = exact_public_right_state_score(
            public_inverse_table,
            key_words,
            guessed_states,
            scan_stage - 1,
            diffs,
        )
        exact.append((score, true_state, per_diff))

    exact.sort(key=lambda item: (-item[0], item[1]))
    exact_true_score = None
    exact_true_rank = None
    if exact:
        exact_true_score = next(score for score, word, _ in exact if word == true_state)
        exact_true_rank = 1 + sum(1 for score, word, _ in exact if word != true_state and score > exact_true_score)

    return {
        "iv": words_to_hex(iv_words),
        "scan_stage": scan_stage,
        "next_stage": scan_stage - 1,
        "true_state": true_state,
        "sampled_true_score": true_sampled_score,
        "sampled_true_rank": sampled_true_rank,
        "sampled_top": sampled_shortlist[: min(8, len(sampled_shortlist))],
        "exact_true_score": exact_true_score,
        "exact_true_rank": exact_true_rank,
        "exact_top": exact[: min(8, len(exact))],
    }


def verify_right_stage_candidate(
    key_words: Sequence[int],
    iv_list: Sequence[Sequence[int]],
    prefix_words: Sequence[int],
    candidate_stage: int,
    candidate_pair: Tuple[int, int],
    known_outer_states: Dict[int, int],
    *,
    diffs: Sequence[int],
    sample_x: Sequence[int],
    sampled_top: int,
    exact_top: int,
) -> Dict[str, object]:
    if candidate_stage < 2 or candidate_stage > 8:
        raise ValueError("candidate_stage must be in 2..8")

    trial_key = list(key_words)
    base = 2 * (candidate_stage - 1)
    trial_key[base], trial_key[base + 1] = candidate_pair

    total_exact = 0
    total_sampled = 0
    recovered = []
    for iv_words in iv_list:
        if candidate_stage == 7 and not known_outer_states:
            result = outer_s8_word_scan(
                key_words,
                list(iv_words),
                prefix_words,
                candidate_pair,
                diffs=diffs,
                sample_x=sample_x,
                sampled_top=sampled_top,
                exact_top=exact_top,
            )
        else:
            result = public_right_state_word_scan(
                trial_key,
                list(iv_words),
                prefix_words,
                candidate_stage + 1,
                known_outer_states,
                oracle_key_words=key_words,
                diffs=diffs,
                sample_x=sample_x,
                sampled_top=sampled_top,
                exact_top=exact_top,
            )
        recovered.append(result)
        total_sampled += int(result["sampled_true_score"])
        if result["exact_true_score"] is not None:
            total_exact += int(result["exact_true_score"])

    return {
        "candidate_stage": candidate_stage,
        "candidate_pair": candidate_pair,
        "total_sampled": total_sampled,
        "total_exact": total_exact,
        "per_iv": recovered,
    }


def injected_right_lane_scan(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    stage_idx: int,
    diffs: Sequence[int],
    sample_x: Sequence[int],
    *,
    class_limit: Optional[int],
    class_seed: int,
    exact: bool,
    exact_top: int,
) -> Dict[str, object]:
    prepared = reduced_right_inverse_table(key_words, iv_words, prefix_words, stage_idx)
    oracle_table = prepared["table"]
    assert isinstance(oracle_table, list)
    state_words = prepared["state"]
    assert isinstance(state_words, list)

    true_pair = stage_key_pair(key_words, stage_idx)
    candidates, total_size, exhaustive, signature = lane_class_candidates(true_pair, stage_idx, class_limit, class_seed)

    scored = []
    total_candidates = max(1, len(candidates))
    for idx, pair in enumerate(candidates, start=1):
        _progress_update(
            f"stage{stage_idx}-scan",
            idx,
            total_candidates,
            f"testing [{int(pair[0]):04X} {int(pair[1]):04X}]",
        )
        if exact:
            score, per_diff = exact_injected_right_score(oracle_table, stage_idx, pair, diffs)
        else:
            score, per_diff = sampled_injected_right_score(oracle_table, stage_idx, pair, diffs, sample_x)
        scored.append((score, pair, per_diff))
    _progress_finish(f"stage{stage_idx}-scan")
    scored.sort(key=lambda item: (-item[0], item[1]))

    true_score = next(score for score, pair, _ in scored if pair == true_pair)
    true_rank = 1 + sum(1 for score, pair, _ in scored if pair != true_pair and score > true_score)
    best_wrong_score = max((score for score, pair, _ in scored if pair != true_pair), default=true_score)

    exact_scored: List[Tuple[int, Tuple[int, int], List[Tuple[int, int, int, int]]]] = []
    if not exact and exact_top > 0:
        shortlisted = [pair for _, pair, _ in scored[:exact_top]]
        if true_pair not in shortlisted:
            shortlisted.append(true_pair)
        total_exact = max(1, len(shortlisted))
        for idx, pair in enumerate(shortlisted, start=1):
            _progress_update(
                f"stage{stage_idx}-exact",
                idx,
                total_exact,
                f"testing [{int(pair[0]):04X} {int(pair[1]):04X}]",
            )
            exact_score, per_diff = exact_injected_right_score(oracle_table, stage_idx, pair, diffs)
            exact_scored.append((exact_score, pair, per_diff))
        _progress_finish(f"stage{stage_idx}-exact")
        exact_scored.sort(key=lambda item: (-item[0], item[1]))

    exact_true_rank = None
    exact_true_score = None
    if exact_scored and any(pair == true_pair for _, pair, _ in exact_scored):
        exact_true_score = next(score for score, pair, _ in exact_scored if pair == true_pair)
        exact_true_rank = 1 + sum(1 for score, pair, _ in exact_scored if pair != true_pair and score > exact_true_score)

    return {
        "iv": words_to_hex(iv_words),
        "stage_idx": stage_idx,
        "true_pair": true_pair,
        "true_state": state_words[stage_idx - 1],
        "lane_signature": signature,
        "class_size": total_size,
        "scanned": len(candidates),
        "class_exhaustive": exhaustive,
        "sampled_top": scored[: min(8, len(scored))],
        "sampled_true_score": true_score,
        "sampled_true_rank": true_rank,
        "sampled_best_wrong": best_wrong_score,
        "exact_top": exact_scored[: min(8, len(exact_scored))],
        "exact_true_rank": exact_true_rank,
        "exact_true_score": exact_true_score,
    }


def search_injected_right_contexts(
    key_words: Sequence[int],
    prefix_words: Sequence[int],
    stage_idx: int,
    diffs: Sequence[int],
    sample_x: Sequence[int],
    *,
    trials: int,
    seed: int,
    class_limit: Optional[int],
    class_seed: int,
) -> List[Dict[str, object]]:
    rng = random.Random(seed)
    results = []
    for trial in range(trials):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        result = injected_right_lane_scan(
            key_words,
            iv_words,
            prefix_words,
            stage_idx,
            diffs,
            sample_x,
            class_limit=class_limit,
            class_seed=class_seed + trial,
            exact=False,
            exact_top=0,
        )
        result["trial"] = trial + 1
        results.append(result)
    results.sort(
        key=lambda item: (
            int(item["sampled_true_rank"]),
            -int(item["sampled_true_score"]),
            int(item["sampled_best_wrong"]),
        )
    )
    return results


def reduced_left_forward_table(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    target_stage: int,
) -> Dict[str, object]:
    ctx = ctx_after_prefix(key_words, iv_words, prefix_words)
    state = ctx["state"]
    assert isinstance(state, list)
    table = next_word_decrypt_table(ctx, key_words)

    for stage_idx in range(1, target_stage):
        pair = stage_key_pair(key_words, stage_idx)
        state_word = int(state[stage_idx - 1]) & 0xFFFF
        peeled = [0] * 0x10000
        for x in range(0x10000):
            peeled[x] = enc_block((int(table[x]) + state_word) & 0xFFFF, pair, stage_idx)
        table = peeled

    return {
        "table": table,
        "state": list(state),
        "target_stage": target_stage,
    }


def sampled_injected_left_score(
    source_table: Sequence[int],
    stage_idx: int,
    pair: Tuple[int, int],
    state_word: int,
    diffs: Sequence[int],
    sample_x: Sequence[int],
) -> Tuple[int, List[Tuple[int, int, int, int]]]:
    total = 0
    per_diff = []
    state_word &= 0xFFFF
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in sample_x:
            left = enc_block((int(source_table[(int(x) + int(diff)) & 0xFFFF]) + state_word) & 0xFFFF, pair, stage_idx)
            right = enc_block((int(source_table[int(x) & 0xFFFF]) + state_word) & 0xFFFF, pair, stage_idx)
            out_diff = (int(left) - int(right)) & 0xFFFF
            counts[out_diff] = counts.get(out_diff, 0) + 1
        best_out, best_count = max(counts.items(), key=lambda item: (item[1], -item[0]))
        total += best_count
        per_diff.append((diff & 0xFFFF, best_out & 0xFFFF, best_count, len(counts)))
    return total, per_diff


def exact_injected_left_score(
    source_table: Sequence[int],
    stage_idx: int,
    pair: Tuple[int, int],
    state_word: int,
    diffs: Sequence[int],
) -> Tuple[int, List[Tuple[int, int, int, int]]]:
    total = 0
    per_diff = []
    state_word &= 0xFFFF
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in range(0x10000):
            left = enc_block((int(source_table[(x + diff) & 0xFFFF]) + state_word) & 0xFFFF, pair, stage_idx)
            right = enc_block((int(source_table[x]) + state_word) & 0xFFFF, pair, stage_idx)
            out_diff = (int(left) - int(right)) & 0xFFFF
            counts[out_diff] = counts.get(out_diff, 0) + 1
        best_out, best_count = max(counts.items(), key=lambda item: (item[1], -item[0]))
        total += best_count
        per_diff.append((diff & 0xFFFF, best_out & 0xFFFF, best_count, len(counts)))
    return total, per_diff


def injected_left_lane_scan(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    stage_idx: int,
    diffs: Sequence[int],
    sample_x: Sequence[int],
    *,
    class_limit: Optional[int],
    class_seed: int,
    exact: bool,
    exact_top: int,
) -> Dict[str, object]:
    prepared = reduced_left_forward_table(key_words, iv_words, prefix_words, stage_idx)
    source_table = prepared["table"]
    assert isinstance(source_table, list)
    state_words = prepared["state"]
    assert isinstance(state_words, list)

    true_pair = stage_key_pair(key_words, stage_idx)
    state_word = int(state_words[stage_idx - 1]) & 0xFFFF
    candidates, total_size, exhaustive, signature = lane_class_candidates(true_pair, stage_idx, class_limit, class_seed)

    scored = []
    for pair in candidates:
        if exact:
            score, per_diff = exact_injected_left_score(source_table, stage_idx, pair, state_word, diffs)
        else:
            score, per_diff = sampled_injected_left_score(source_table, stage_idx, pair, state_word, diffs, sample_x)
        scored.append((score, pair, per_diff))
    scored.sort(key=lambda item: (-item[0], item[1]))

    true_score = next(score for score, pair, _ in scored if pair == true_pair)
    true_rank = 1 + sum(1 for score, pair, _ in scored if pair != true_pair and score > true_score)
    best_wrong_score = max((score for score, pair, _ in scored if pair != true_pair), default=true_score)

    exact_scored: List[Tuple[int, Tuple[int, int], List[Tuple[int, int, int, int]]]] = []
    if not exact and exact_top > 0:
        shortlisted = [pair for _, pair, _ in scored[:exact_top]]
        if true_pair not in shortlisted:
            shortlisted.append(true_pair)
        for pair in shortlisted:
            exact_score, per_diff = exact_injected_left_score(source_table, stage_idx, pair, state_word, diffs)
            exact_scored.append((exact_score, pair, per_diff))
        exact_scored.sort(key=lambda item: (-item[0], item[1]))

    exact_true_rank = None
    exact_true_score = None
    if exact_scored and any(pair == true_pair for _, pair, _ in exact_scored):
        exact_true_score = next(score for score, pair, _ in exact_scored if pair == true_pair)
        exact_true_rank = 1 + sum(1 for score, pair, _ in exact_scored if pair != true_pair and score > exact_true_score)

    return {
        "iv": words_to_hex(iv_words),
        "stage_idx": stage_idx,
        "true_pair": true_pair,
        "true_state": state_word,
        "lane_signature": signature,
        "class_size": total_size,
        "scanned": len(candidates),
        "class_exhaustive": exhaustive,
        "sampled_top": scored[: min(8, len(scored))],
        "sampled_true_score": true_score,
        "sampled_true_rank": true_rank,
        "sampled_best_wrong": best_wrong_score,
        "exact_top": exact_scored[: min(8, len(exact_scored))],
        "exact_true_rank": exact_true_rank,
        "exact_true_score": exact_true_score,
    }


def search_injected_left_contexts(
    key_words: Sequence[int],
    prefix_words: Sequence[int],
    stage_idx: int,
    diffs: Sequence[int],
    sample_x: Sequence[int],
    *,
    trials: int,
    seed: int,
    class_limit: Optional[int],
    class_seed: int,
) -> List[Dict[str, object]]:
    rng = random.Random(seed)
    results = []
    for trial in range(trials):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        result = injected_left_lane_scan(
            key_words,
            iv_words,
            prefix_words,
            stage_idx,
            diffs,
            sample_x,
            class_limit=class_limit,
            class_seed=class_seed + trial,
            exact=False,
            exact_top=0,
        )
        result["trial"] = trial + 1
        results.append(result)
    results.sort(
        key=lambda item: (
            int(item["sampled_true_rank"]),
            -int(item["sampled_true_score"]),
            int(item["sampled_best_wrong"]),
        )
    )
    return results


def print_scan(result: Dict[str, object]) -> None:
    print(
        f"Injected right scan: iv={result['iv']} stage=K{result['stage_idx']} "
        f"true_pair={result['true_pair']} true_state={int(result['true_state']):04X}"
    )
    print(
        f"  lane class size={result['class_size']} scanned={result['scanned']} "
        f"exhaustive={result['class_exhaustive']} sig={result['lane_signature']}"
    )
    print(
        f"  sampled true rank={result['sampled_true_rank']} "
        f"true={result['sampled_true_score']} best_wrong={result['sampled_best_wrong']}"
    )
    sampled_top = result["sampled_top"]
    assert isinstance(sampled_top, list)
    for score, pair, per_diff in sampled_top:
        marker = "  <-- true" if pair == result["true_pair"] else ""
        print(f"  sampled pair={pair} score={score}{marker}")
        print(f"    per-diff={per_diff}")

    exact_top = result["exact_top"]
    assert isinstance(exact_top, list)
    if exact_top:
        print(
            f"  exact true rank={result['exact_true_rank']} "
            f"true={result['exact_true_score']}"
        )
        for score, pair, per_diff in exact_top:
            marker = "  <-- true" if pair == result["true_pair"] else ""
            print(f"  exact pair={pair} score={score}{marker}")
            print(f"    per-diff={per_diff}")


def print_left_scan(result: Dict[str, object]) -> None:
    print(
        f"Injected left scan: iv={result['iv']} stage=K{result['stage_idx']} "
        f"true_pair={result['true_pair']} true_state={int(result['true_state']):04X}"
    )
    print(
        f"  lane class size={result['class_size']} scanned={result['scanned']} "
        f"exhaustive={result['class_exhaustive']} sig={result['lane_signature']}"
    )
    print(
        f"  sampled true rank={result['sampled_true_rank']} "
        f"true={result['sampled_true_score']} best_wrong={result['sampled_best_wrong']}"
    )
    sampled_top = result["sampled_top"]
    assert isinstance(sampled_top, list)
    for score, pair, per_diff in sampled_top:
        marker = "  <-- true" if pair == result["true_pair"] else ""
        print(f"  sampled pair={pair} score={score}{marker}")
        print(f"    per-diff={per_diff}")

    exact_top = result["exact_top"]
    assert isinstance(exact_top, list)
    if exact_top:
        print(
            f"  exact true rank={result['exact_true_rank']} "
            f"true={result['exact_true_score']}"
        )
        for score, pair, per_diff in exact_top:
            marker = "  <-- true" if pair == result["true_pair"] else ""
            print(f"  exact pair={pair} score={score}{marker}")
            print(f"    per-diff={per_diff}")


def print_support_collapse_scan(result: Dict[str, object]) -> None:
    print(
        f"Support-collapse scan: iv={result['iv']} stage=K{result['target_stage']} "
        f"true_pair={result['true_pair']} true_state={int(result['true_state']):04X}"
    )
    print(
        f"  rows={[f'{int(row):02X}' for row in result['rows']]} "
        f"true_rank={result['true_rank']} true_ties={result['true_ties']} "
        f"true_score={result['true_score']}"
    )
    top_pairs = result["top_pairs"]
    assert isinstance(top_pairs, list)
    for total, pair, details in top_pairs:
        marker = "  <-- true" if tuple(pair) == result["true_pair"] else ""
        print(f"  pair={pair} total_support={int(total)}{marker}")
        print(f"    row_details={details}")


def print_public_state_scan(result: Dict[str, object]) -> None:
    print(
        f"Public right-state byte scan: iv={result['iv']} stage=s{result['scan_stage']} "
        f"next=K{result['next_stage']} part={result['part']} true_state={int(result['true_state']):04X}"
    )
    print(
        f"  fixed other byte={int(result['fixed_other_byte']):02X} "
        f"sampled true rank={result['sampled_true_rank']} "
        f"sampled true score={result['sampled_true_score']}"
    )
    sampled_top = result["sampled_top"]
    assert isinstance(sampled_top, list)
    for score, byte, guess_word, per_diff in sampled_top:
        marker = "  <-- true" if byte == result["true_byte"] else ""
        print(f"  sampled byte={byte:02X} guess={guess_word:04X} score={score}{marker}")
        print(f"    per-diff={per_diff}")

    exact_top = result["exact_top"]
    assert isinstance(exact_top, list)
    if exact_top:
        print(
            f"  exact true rank={result['exact_true_rank']} "
            f"exact true score={result['exact_true_score']}"
        )
        for score, byte, guess_word, per_diff in exact_top:
            marker = "  <-- true" if byte == result["true_byte"] else ""
            print(f"  exact byte={byte:02X} guess={guess_word:04X} score={score}{marker}")
            print(f"    per-diff={per_diff}")


def print_public_state_word_scan(result: Dict[str, object]) -> None:
    print(
        f"Public right-state word scan: iv={result['iv']} stage=s{result['scan_stage']} "
        f"next=K{result['next_stage']} true_state={int(result['true_state']):04X}"
    )
    print(
        f"  sampled true rank={result['sampled_true_rank']} "
        f"sampled true score={result['sampled_true_score']}"
    )
    sampled_top = result["sampled_top"]
    assert isinstance(sampled_top, list)
    for score, word in sampled_top:
        marker = "  <-- true" if word == result["true_state"] else ""
        print(f"  sampled word={word:04X} score={score}{marker}")

    exact_top = result["exact_top"]
    assert isinstance(exact_top, list)
    if exact_top:
        print(
            f"  exact true rank={result['exact_true_rank']} "
            f"exact true score={result['exact_true_score']}"
        )
        for score, word, per_diff in exact_top:
            marker = "  <-- true" if word == result["true_state"] else ""
            print(f"  exact word={word:04X} score={score}{marker}")
            print(f"    per-diff={per_diff}")


def print_candidate_verify(result: Dict[str, object]) -> None:
    print(
        f"Right-stage candidate verify: stage=K{result['candidate_stage']} "
        f"pair={result['candidate_pair']} total_sampled={result['total_sampled']} "
        f"total_exact={result['total_exact']}"
    )
    per_iv = result["per_iv"]
    assert isinstance(per_iv, list)
    for entry in per_iv:
        print_public_state_word_scan(entry)
        print()


def print_related_state_validation(result: Dict[str, object]) -> None:
    print("Exact related-state family validation")
    print(f"  delta={int(result['delta']):04X}")
    print(
        f"  one-word encryption checks passed: {result['encrypt_checks']}"
        f" | one-word decryption checks passed: {result['decrypt_checks']}"
    )
    print(
        f"  second-word encryption stage-3 exposures passed: {result['encrypt_second_round_checks']}"
        f" | second-word decryption stage-2 exposures passed: {result['decrypt_second_round_checks']}"
    )
    post_round_state_delta = result["post_round_state_delta"]
    assert isinstance(post_round_state_delta, list)
    print(f"  post-round state delta: {words_to_hex(post_round_state_delta)}")


def print_related_iv_search(result: Dict[str, object]) -> None:
    print("Related-IV fingerprint search")
    print(
        f"  delta={int(result['delta']):04X} trials={result['trials']} "
        f"probes={','.join(f'{int(word):04X}' for word in result['probe_words'])}"
    )
    matches = result["matches"]
    assert isinstance(matches, list)
    print(f"  fingerprint matches: {len(matches)}")
    for entry in matches[: min(8, len(matches))]:
        print(
            f"  left_iv={entry['left_iv']} right_iv={entry['right_iv']} "
            f"fingerprint={entry['fingerprint']}"
        )
        if "truth_state_delta" in entry:
            print(
                f"    truth_state_delta={words_to_hex(entry['truth_state_delta'])} "
                f"truth_lfsr_delta={int(entry['truth_lfsr_delta']):04X} "
                f"is_exact_s1_pair={entry['is_exact_s1_pair']}"
            )


def print_public_iv_candidate(result: Dict[str, object]) -> None:
    print(f"Public IV candidate: iv={words_to_hex(result['iv'])}")
    raw_enc = result["raw_enc"]
    raw_dec = result["raw_dec"]
    assert isinstance(raw_enc, tuple)
    assert isinstance(raw_dec, tuple)
    print(
        f"  chosen-IV rows: enc={float(result['row_enc']):.2f} dec={float(result['row_dec']):.2f}"
    )
    print(
        f"  raw nibble enc=(xor={int(raw_enc[0])}, add={int(raw_enc[1])}, support={int(raw_enc[2])}) "
        f"dec=(xor={int(raw_dec[0])}, add={int(raw_dec[1])}, support={int(raw_dec[2])})"
    )
    pair_results = result["pair_results"]
    assert isinstance(pair_results, dict)
    for name, entry in pair_results.items():
        print(
            f"  pair[{name}]: "
            f"enc_hits={int(entry['enc_hits'])} enc_best={int(entry['enc_best_count'])}@{int(entry['enc_best_diff']):04X} enc_support={int(entry['enc_support'])} "
            f"dec_hits={int(entry['dec_hits'])} dec_best={int(entry['dec_best_count'])}@{int(entry['dec_best_diff']):04X} dec_support={int(entry['dec_support'])}"
        )
        if "is_exact_s1_pair" in entry:
            print(
                f"    truth_state_delta={words_to_hex(entry['truth_state_delta'])} "
                f"truth_lfsr_delta={int(entry['truth_lfsr_delta']):04X} "
                f"is_exact_s1_pair={entry['is_exact_s1_pair']}"
            )


def print_outer_bootstrap_iv(iv_item: Dict[str, object], result: Dict[str, object]) -> None:
    summary = iv_item["summary"]
    assert isinstance(summary, dict)
    print(f"Outer bootstrap IV: iv={words_to_hex(iv_item['iv'])}")
    print(
        f"  public rows: enc={float(summary['row_enc']):.2f} dec={float(summary['row_dec']):.2f} "
        f"raw=({int(summary['raw_nibble_xor'])},{int(summary['raw_nibble_add'])},{int(summary['raw_nibble_support'])})"
    )
    print(
        f"  nibble ties: best={int(summary['best_nibble_tie_count'])} "
        f"near-best={int(summary['near_best_nibble_count'])}"
    )
    if "true_nibble_rank" in summary:
        print(
            f"  true signature={summary['true_signature']} "
            f"rank={int(summary['true_nibble_rank'])} "
            f"score={summary['true_nibble_score']}"
        )
    print(
        f"  true signature beam rank={int(result['true_signature_rank'])} "
        f"beam_hit={result['true_signature'] in result['shortlisted_signatures']}"
    )
    print(
        f"  best pair={result['best_pair']} true={result['true_pair']} "
        f"success={result['success']}"
    )
    print(
        f"  verifier={result.get('verifier_kind', 'exact')} "
        f"rows={','.join(f'{int(v):02X}' for v in result.get('verifier_rows', []))}"
    )
    if result["true_exact_rank"] is not None:
        print(
            f"  true verifier rank={int(result['true_exact_rank'])} "
            f"true verifier score={int(result['true_exact_score'])}"
        )
    exact_scores = result["exact_scores"]
    assert isinstance(exact_scores, list)
    for score, pair, details in exact_scores[: min(6, len(exact_scores))]:
        marker = "  <-- true" if pair == result["true_pair"] else ""
        print(f"  verifier pair={pair} score={score}{marker}")
        print(f"    details={details}")


def print_outer_bootstrap_aggregate(result: Dict[str, object]) -> None:
    print("Aggregated outer bootstrap")
    print(
        f"  best pair={result['best_pair']} true={result['true_pair']} "
        f"success={result['success']}"
    )
    print(
        f"  verifier={result.get('verifier_kind', 'exact')} "
        f"rows={','.join(f'{int(v):02X}' for v in result.get('verifier_rows', []))}"
    )
    if result["true_rank"] is not None:
        print(
            f"  true total verifier={int(result['true_total_exact'])} "
            f"true rank={int(result['true_rank'])}"
        )
    aggregate_scores = result["aggregate_scores"]
    assert isinstance(aggregate_scores, list)
    for score, pair, _ in aggregate_scores[: min(8, len(aggregate_scores))]:
        marker = "  <-- true" if pair == result["true_pair"] else ""
        print(f"  total verifier pair={pair} score={score}{marker}")


def print_k8_pivot(result: Dict[str, object]) -> None:
    best_pair = result["best_pair"]
    true_pair = result["true_pair"]
    success = bool(result["success"])
    if best_pair is None:
        info(f"K8 bootstrap failed on iv={result['iv']} prefix={words_to_hex(result['prefix'])}")
        return
    (good if success else info)(
        f"K8 bootstrap winner {format_pair(best_pair)} on iv={result['iv']} prefix={words_to_hex(result['prefix'])}"
    )
    detail(f"true      = {format_pair(true_pair)}")
    detail(f"candidates = {int(result['candidate_count'])}")
    if result["true_rank"] is not None:
        detail(f"true rank  = {int(result['true_rank'])}")
        detail(f"true score = {int(result['true_score'])}")
    refined = result["refined"]
    assert isinstance(refined, list)
    if refined:
        score, pair, tau, cycle, cycle_score, _details = refined[0]
        detail(f"winner score = {int(score)}")
        detail(f"winner tau   = {int(tau):02X}")
        detail(
            f"winner cycle = {''.join(format(int(v) & 0xF, 'X') for v in cycle)} "
            f"(cycle score {int(cycle_score)})"
        )


def print_reduced_projected_cycle_scan(result: Dict[str, object]) -> None:
    best_pair = result["best_pair"]
    true_pair = result["true_pair"]
    stage_idx = int(result["target_stage"])
    success = bool(result["success"])
    if best_pair is None:
        info(f"stage {stage_idx} reduced pivot found no candidates")
        return
    (good if success else info)(
        f"stage {stage_idx} winner {format_pair(best_pair)} on iv={result['iv']} prefix={words_to_hex(result['prefix'])}"
    )
    detail(f"true      = {format_pair(true_pair)}")
    detail(f"candidates = {int(result['candidate_count'])}")
    if result["true_rank"] is not None:
        detail(f"true rank  = {int(result['true_rank'])}")
        detail(f"true score = {int(result['true_score'])}")
    refined = result["refined"]
    assert isinstance(refined, list)
    if refined:
        score, _pair, cycle, cycle_score, _details = refined[0]
        detail(f"winner score = {int(score)}")
        detail(
            f"winner cycle = {''.join(format(int(v) & 0xF, 'X') for v in cycle)} "
            f"(cycle score {int(cycle_score)})"
        )


def print_recursive_public_context_recovery(result: Dict[str, object]) -> None:
    info(
        f"recursive public recovery on iv={result['iv']} prefix={words_to_hex(result['prefix'])} "
        f"down to stage {int(result['target_stage'])}"
    )
    stage_rows = result["stage_rows"]
    assert isinstance(stage_rows, list)
    for row in stage_rows:
        assert isinstance(row, dict)
        best = row["best"]
        stage_idx = int(row["stage"])
        true_pair = row["true_pair"]
        true_state = int(row["true_state"]) & 0xFFFF
        if best is not None:
            assert isinstance(best, dict)
            best_pair = tuple(best["pair"])
            best_state = int(best["state_word"]) & 0xFFFF
            success = (best_pair == true_pair and best_state == true_state)
            (good if success else info)(
                f"stage {stage_idx} winner {format_pair(best_pair)} / state {best_state:04X}"
            )
            detail(f"true      = {format_pair(true_pair)} / state {true_state:04X}")
            detail(f"true rank  = {row['true_rank']}")
            detail(f"candidates = {int(row['candidate_count'])}")
            detail(f"winner score = {int(best['verifier_score'])}")
            detail(f"cycle rank   = {int(best['cycle_rank'])}")
        else:
            info(f"stage {stage_idx} produced no candidates")


def print_recursive_context_search(result: Dict[str, object]) -> None:
    print(
        f"Context search: mode={result['mode']} target_stage={int(result['target_stage'])} "
        f"contexts={int(result['contexts_scanned'])}"
    )
    entries = result["entries"]
    assert isinstance(entries, list)
    for idx, entry in enumerate(entries[: min(12, len(entries))], start=1):
        assert isinstance(entry, dict)
        print(
            f"  {idx}. {entry['label']} reached={entry['reached_target']} ready_stage={int(entry['ready_stage'])} "
            f"candidates={int(entry['candidate_count'])} best_score={int(entry['best_score'])} "
            f"true_rank={entry.get('true_rank')}"
        )
        if entry.get("verifier_gap") is not None or entry.get("low_gap") is not None or entry.get("cycle_gap") is not None:
            print(
                f"     verifier_gap={entry.get('verifier_gap')} low_gap={entry.get('low_gap')} "
                f"cycle_gap={entry.get('cycle_gap')}"
            )
        candidate_pairs = entry["candidate_pairs"]
        assert isinstance(candidate_pairs, list)
        if candidate_pairs:
            print(f"     pairset={candidate_pairs[: min(8, len(candidate_pairs))]}")
    intersections = result["intersections"]
    assert isinstance(intersections, list)
    if intersections:
        print("  intersections:")
        for row in intersections:
            assert isinstance(row, dict)
            print(
                f"    top{int(row['contexts_used'])}: size={int(row['intersection_size'])} "
                f"true_survives={row['true_survives']} from={row['context']}"
            )
            pairs = row["pairs"]
            assert isinstance(pairs, list)
            if pairs:
                print(f"      pairs={pairs}")


def print_stage1_finish_scan(result: Dict[str, object]) -> None:
    info(
        f"stage 1 finish on iv={result['iv']} prefix={words_to_hex(result['prefix'])} "
        f"with known K2={format_pair(result['k2_pair'])}"
    )
    recovered = result["recovered"]
    assert isinstance(recovered, list)
    detail(f"true      = {format_pair(result['true_k1'])} / state {int(result['true_s1']):04X}")
    detail(f"true rank  = {result['true_rank']}")
    detail(f"candidates = {len(recovered)}")
    if recovered:
        item = recovered[0]
        assert isinstance(item, dict)
        success = (int(item["k0"]), int(item["k1"])) == tuple(int(x) for x in result["true_k1"]) and int(item["state_word"]) == int(result["true_s1"])
        (good if success else info)(
            f"stage 1 winner {format_pair((int(item['k0']), int(item['k1'])))} / state {int(item['state_word']):04X}"
        )


def print_transport_validation(rows: Sequence[Dict[str, object]]) -> None:
    print("Exact upper-transport validation")
    total_stage_checks = 0
    total_upper = 0
    total_canonical = 0
    for row in rows:
        stages = row["stages"]
        assert isinstance(stages, dict)
        stage_items = []
        for stage_idx in sorted(stages):
            entry = stages[stage_idx]
            assert isinstance(entry, dict)
            total_stage_checks += 1
            total_upper += 1 if bool(entry["upper_match"]) else 0
            total_canonical += 1 if bool(entry["canonical_match"]) else 0
            marker = "ok" if entry["upper_match"] else "fail"
            stage_items.append(f"{stage_idx}:{marker}")
        print(
            f"  trial {int(row['trial'])}: iv={row['iv']} "
            f"all_upper_match={row['all_upper_match']} stages={' '.join(stage_items)}"
        )
    if total_stage_checks:
        print(
            f"  upper multiset matches: {total_upper}/{total_stage_checks} "
            f"canonical matches: {total_canonical}/{total_stage_checks}"
        )


def print_transport_pair_scan(result: Dict[str, object]) -> None:
    print(
        f"Transport pair scan: iv={result['iv']} stage={int(result['target_stage'])} "
        f"true_pair={result['true_pair']} true_state={int(result['true_state']):04X}"
    )
    print(
        f"  true_low={int(result['true_low']):02X} low_rank={int(result['low_true_rank'])} "
        f"true_high={int(result['true_high']):02X} true_pair_rank={int(result['true_rank'])}"
    )
    top_pairs = result["top_pairs"]
    assert isinstance(top_pairs, list)
    for idx, item in enumerate(top_pairs, start=1):
        marker = "  <-- true" if tuple(item["pair"]) == result["true_pair"] else ""
        shift_text = "None" if item["best_shift"] is None else f"{int(item['best_shift']):02X}"
        print(
            f"  #{idx}: pair={item['pair']} full_match={item['full_match']} "
            f"match_count={int(item['match_count'])} canonical_count={int(item['canonical_count'])} "
            f"best_shift={shift_text}{marker}"
        )


def run_demo(
    key_words: Sequence[int],
    prefix_words: Sequence[int],
    diffs: Sequence[int],
    sample_x: Sequence[int],
    class_limit: Optional[int],
    class_seed: int,
    exact_top: int,
) -> None:
    set_progress_enabled(True)
    info("exact injected right ladder demo")
    info("injecting true reduced outer states into every stage solve (cheating)")

    recovered_pairs: Dict[int, Tuple[int, int]] = {}
    try:
        for stage_idx in range(8, 0, -1):
            iv_words = parse_full_iv_hex(KNOWN_STAGE_IVS[stage_idx])
            info(f"attacking stage {stage_idx} on iv={words_to_hex(iv_words)}")
            detail("injecting true reduced state for this stage solve (cheating)")
            result = injected_right_lane_scan(
                key_words,
                iv_words,
                prefix_words,
                stage_idx,
                diffs,
                sample_x,
                class_limit=class_limit,
                class_seed=class_seed,
                exact=False,
                exact_top=exact_top,
            )
            winner = choose_injected_stage_winner(result)
            true_pair = tuple(int(x) for x in result["true_pair"])
            sampled_rank = result["sampled_true_rank"]
            exact_rank = result["exact_true_rank"]
            if winner is None:
                info(f"stage {stage_idx} produced no winner")
                continue
            recovered_pairs[stage_idx] = winner
            if winner == true_pair:
                good(f"stage {stage_idx} winner {format_pair(winner)}")
            else:
                info(f"stage {stage_idx} winner {format_pair(winner)}")
            detail(f"true       = {format_pair(true_pair)}")
            detail(f"sampled rk = {sampled_rank}")
            if exact_rank is not None:
                detail(f"exact rk   = {exact_rank}")
            exact_top_rows = result.get("exact_top")
            if isinstance(exact_top_rows, list) and exact_top_rows:
                detail(f"winner score = {int(exact_top_rows[0][0])}")
                if result.get("exact_true_score") is not None:
                    detail(f"true score   = {int(result['exact_true_score'])}")
            sampled_top_rows = result.get("sampled_top")
            if (not exact_top_rows) and isinstance(sampled_top_rows, list) and sampled_top_rows:
                detail(f"winner score = {int(sampled_top_rows[0][0])}")
                detail(f"true score   = {int(result['sampled_true_score'])}")
    finally:
        set_progress_enabled(False)

    recovered_key_words = assemble_key_words_from_stage_pairs(recovered_pairs, key_words)
    recovered_key_hex = key_words_to_hex(recovered_key_words)
    true_key_hex = key_words_to_hex(key_words)
    if recovered_key_words == list(key_words):
        good("recovered full segment-key ladder matches the oracle key")
    else:
        info("recovered key differs from the oracle key")
    detail(f"recovered key = {recovered_key_hex}")
    detail(f"true key      = {true_key_hex}")

    verify_iv = parse_full_iv_hex(KNOWN_STAGE_IVS[8])
    verify_pts = [0x0000, 0x1111, 0x2222, 0x3333]
    verification = verify_full_key_against_oracle(recovered_key_words, key_words, verify_iv, verify_pts)
    if verification["match"]:
        good("oracle verification passed")
    else:
        info("oracle verification failed")
    detail(f"iv   = {words_to_hex(verification['iv'])}")
    detail(f"pt   = {words_to_hex(verification['pt'])}")
    detail(f"ct*  = {words_to_hex(verification['candidate_ct'])}")
    detail(f"ct   = {words_to_hex(verification['oracle_ct'])}")


def print_core_recovery(result: Dict[str, object], true_state: Sequence[int], true_lfsr: Optional[int] = None) -> None:
    full_state = result["full_state"]
    assert isinstance(full_state, list)
    print(f"  recovered full state: {words_to_hex(full_state)}")
    print(f"  true      full state: {words_to_hex(true_state)}")
    trace_parts = [
        f"v12={int(result['v12']):04X}",
        f"v23={int(result['v23']):04X}",
        f"v34={int(result['v34']):04X}",
        f"v45={int(result['v45']):04X}",
        f"v56={int(result['v56']):04X}",
        f"v67={int(result['v67']):04X}",
    ]
    if "v78" in result:
        trace_parts.append(f"v78={int(result['v78']):04X}")
    print("  traces: " + " ".join(trace_parts))
    if true_lfsr is not None and "lfsr1" in result:
        print(f"  recovered lfsr step: {int(result['lfsr1']):04X}")
        print(f"  true      lfsr step: {true_lfsr:04X}")


def print_low_byte_scan(result: Dict[str, object]) -> None:
    pair = result["candidate_pair"]
    assert isinstance(pair, tuple)
    print("Exact stage low-byte scan")
    print(f"  iv={result['iv']} stage={int(result['target_stage'])}")
    print(f"  candidate_pair=({int(pair[0]):04X},{int(pair[1]):04X})")
    print(f"  true_state={int(result['true_state']):04X} true_low={int(result['true_low']):02X}")
    print(f"  true_rank={int(result['true_rank'])} true_total_support={int(result['true_total_support'])}")
    print("  top candidates:")
    for idx, item in enumerate(result["top"], start=1):
        assert isinstance(item, dict)
        rows = item["sample_rows"]
        assert isinstance(rows, tuple)
        marker = "  <-- true" if int(item["low"]) == int(result["true_low"]) else ""
        print(
            f"    #{idx} low={int(item['low']):02X} total_support={int(item['total_support'])}"
            f" sample_rows=({int(rows[0])},{int(rows[1])},{int(rows[2])},{int(rows[3])}){marker}"
        )


def print_high_byte_scan(result: Dict[str, object]) -> None:
    pair = result["candidate_pair"]
    assert isinstance(pair, tuple)
    print("Exact stage high-byte / next-key scan")
    print(f"  iv={result['iv']} stage={int(result['target_stage'])}")
    print(f"  candidate_pair=({int(pair[0]):04X},{int(pair[1]):04X})")
    print(
        f"  true_state={int(result['true_state']):04X} true_low={int(result['true_low']):02X}"
        f" used_low={int(result['used_low']):02X} low_true_rank={int(result['low_true_rank'])}"
    )
    if "candidate_next_pair" in result:
        next_pair = result["candidate_next_pair"]
        assert isinstance(next_pair, tuple)
        print(f"  next_pair=({int(next_pair[0]):04X},{int(next_pair[1]):04X}) score_kind={result['score_kind']}")
        print(f"  true_high={int(result['true_high']):02X} true_high_rank={int(result['true_high_rank'])}")
        print("  top high candidates:")
        for idx, item in enumerate(result["top_highs"], start=1):
            assert isinstance(item, dict)
            marker = "  <-- true" if int(item["high"]) == int(result["true_high"]) else ""
            line = f"    #{idx} high={int(item['high']):02X} score={int(item['score'])}"
            if "best_delta" in item:
                line += f" best_delta={int(item['best_delta']):04X}"
            elif "sample_rows" in item:
                rows = item["sample_rows"]
                assert isinstance(rows, tuple)
                row_bits = ",".join(f"{int(row):02X}:{int(support)}/{int(low):02X}" for row, support, low in rows)
                line += f" sample_rows=({row_bits})"
            print(line + marker)
        return

    print(f"  true_high={int(result['true_high']):02X} true_next_pair={result['true_next_pair']} score_kind={result['score_kind']}")
    print(f"  true_pair_rank={int(result['true_pair_rank'])}")
    print("  top next-key candidates:")
    for idx, item in enumerate(result["top_pairs"], start=1):
        assert isinstance(item, dict)
        next_pair = item["pair"]
        assert isinstance(next_pair, tuple)
        marker = "  <-- true pair" if next_pair == result["true_next_pair"] else ""
        line = (
            f"    #{idx} next_pair=({int(next_pair[0]):04X},{int(next_pair[1]):04X})"
            f" score={int(item['score'])} best_high={int(item['best_high']):02X}"
        )
        if "best_delta" in item:
            line += f" best_delta={int(item['best_delta']):04X}"
        elif "sample_rows" in item:
            rows = item["sample_rows"]
            assert isinstance(rows, tuple)
            row_bits = ",".join(f"{int(row):02X}:{int(support)}" for row, support, _ in rows)
            line += f" sample_rows=({row_bits})"
        print(line + marker)


def print_recursive_pair_scan(result: Dict[str, object]) -> None:
    pair = result["candidate_pair"]
    assert isinstance(pair, tuple)
    print("Recursive exact pair scan")
    print(f"  iv={result['iv']} stage={int(result['target_stage'])}")
    print(f"  candidate_pair=({int(pair[0]):04X},{int(pair[1]):04X})")
    print(
        f"  true_state={int(result['true_state']):04X} true_low={int(result['true_low']):02X}"
        f" true_high={int(result['true_high']):02X} used_low={int(result['used_low']):02X}"
        f" low_true_rank={int(result['low_true_rank'])}"
    )
    print(f"  true_next_pair={result['true_next_pair']} true_next_low={int(result['true_next_low']):02X}")
    print(f"  true_pair_rank={int(result['true_pair_rank'])}")
    print("  top next-key candidates:")
    for idx, item in enumerate(result["top_pairs"], start=1):
        assert isinstance(item, dict)
        next_pair = item["pair"]
        assert isinstance(next_pair, tuple)
        marker = "  <-- true pair" if next_pair == result["true_next_pair"] else ""
        line = (
            f"    #{idx} next_pair=({int(next_pair[0]):04X},{int(next_pair[1]):04X})"
            f" high_score={int(item['high_score'])} best_high={int(item['best_high']):02X}"
            f" next_low={int(item['next_low']):02X} next_low_score={int(item['next_low_score'])}"
            f" next_low_gap={int(item['next_low_gap'])}"
        )
        if item.get("true_next_low_rank") is not None:
            line += f" true_next_low_rank={int(item['true_next_low_rank'])}"
        print(line + marker)


def choose_injected_stage_winner(result: Dict[str, object]) -> Optional[Tuple[int, int]]:
    exact_top = result.get("exact_top")
    if isinstance(exact_top, list) and exact_top:
        return tuple(int(x) for x in exact_top[0][1])
    sampled_top = result.get("sampled_top")
    if isinstance(sampled_top, list) and sampled_top:
        return tuple(int(x) for x in sampled_top[0][1])
    return None


def assemble_key_words_from_stage_pairs(
    stage_pairs: Dict[int, Tuple[int, int]],
    fallback_key_words: Optional[Sequence[int]] = None,
) -> List[int]:
    out = list(fallback_key_words) if fallback_key_words is not None else [0] * 16
    if len(out) != 16:
        raise ValueError("full key must contain 16 words")
    for stage_idx, pair in stage_pairs.items():
        base = 2 * (int(stage_idx) - 1)
        out[base] = int(pair[0]) & 0xFFFF
        out[base + 1] = int(pair[1]) & 0xFFFF
    return out


def verify_full_key_against_oracle(
    candidate_key_words: Sequence[int],
    oracle_key_words: Sequence[int],
    iv_words: Sequence[int],
    plaintext_words: Sequence[int],
) -> Dict[str, object]:
    cand_ctx = separ_initial_ctx(candidate_key_words, iv_words)
    oracle_ctx = separ_initial_ctx(oracle_key_words, iv_words)
    cand_ct = [separ_encrypt_word(int(word) & 0xFFFF, cand_ctx, candidate_key_words) for word in plaintext_words]
    oracle_ct = [separ_encrypt_word(int(word) & 0xFFFF, oracle_ctx, oracle_key_words) for word in plaintext_words]
    return {
        "match": cand_ct == oracle_ct,
        "candidate_ct": cand_ct,
        "oracle_ct": oracle_ct,
        "iv": list(iv_words),
        "pt": [int(word) & 0xFFFF for word in plaintext_words],
    }


def run_outer4_demo(key_words: Sequence[int], iv_words: Sequence[int], prefix_words: Sequence[int], word_sequence: Sequence[int]) -> None:
    if len(word_sequence) < 2:
        raise ValueError("outer4-demo needs at least two plaintext words")

    ctx = ctx_after_prefix(key_words, iv_words, prefix_words)
    state0 = list(ctx["state"])
    assert isinstance(state0, list)
    pt0 = word_sequence[0] & 0xFFFF
    separ_encrypt_word(pt0, ctx, key_words)
    state1 = list(ctx["state"])
    lfsr1 = int(ctx["lfsr"])

    pt1 = word_sequence[1] & 0xFFFF
    separ_encrypt_word(pt1, ctx, key_words)
    state2 = list(ctx["state"])

    outer0 = outer4(state0)
    outer1 = outer4(state1)
    outer2 = outer4(state2)

    print("Exact 4-word outer-even reconstruction demo")
    print(f"  iv={words_to_hex(iv_words)} prefix={words_to_hex(prefix_words)}")
    print(f"  pt0={pt0:04X} pt1={pt1:04X}")
    print(f"  outer0={words_to_hex(outer0)}")
    print(f"  outer1={words_to_hex(outer1)}")
    print(f"  outer2={words_to_hex(outer2)}")

    first = recover_round_state_from_outer4_pair(key_words, pt0, outer0, outer1)
    second = recover_round_state_from_outer4_pair(key_words, pt1, outer1, outer2)
    combined = recover_lfsr_from_outer4_triplet(key_words, pt0, pt1, outer0, outer1, outer2)

    print("Round 0 reconstruction:")
    print_core_recovery(first, state0)
    print("Round 1 reconstruction:")
    print_core_recovery(second, state1)
    print("LFSR recovery from two adjacent outer-even pairs:")
    print(f"  recovered lfsr step: {int(combined['lfsr1']):04X}")
    print(f"  true      lfsr step: {lfsr1:04X}")


def run_suffix_bridge_demo(key_words: Sequence[int], iv_words: Sequence[int], prefix_words: Sequence[int], word_sequence: Sequence[int]) -> None:
    if len(word_sequence) < 1:
        raise ValueError("suffix-bridge-demo needs at least one plaintext word")

    ctx = ctx_after_prefix(key_words, iv_words, prefix_words)
    state0 = list(ctx["state"])
    assert isinstance(state0, list)
    pt0 = word_sequence[0] & 0xFFFF
    ct0 = separ_encrypt_word(pt0, ctx, key_words)
    state1 = list(ctx["state"])

    bridge = recover_round_suffix_bridge(key_words, pt0, ct0, suffix4(state0), suffix3(state1))
    free_family = solve_suffix_bridge_family(bridge, max_models=2)
    fixed_family = solve_suffix_bridge_family(bridge, next_s4=state1[3], max_models=2)
    recovered = recover_round_state_from_suffix_bridge_and_next_s4(key_words, bridge, state1[3])

    print("Exact suffix-bridge reconstruction demo")
    print(f"  iv={words_to_hex(iv_words)} prefix={words_to_hex(prefix_words)}")
    print(f"  pt0={pt0:04X} ct0={ct0:04X}")
    print(f"  suffix0={words_to_hex(suffix4(state0))}")
    print(f"  next-tail={words_to_hex(suffix3(state1))}")
    print(
        f"  recovered v12={int(bridge['v12']):04X} v23={int(bridge['v23']):04X}"
        f" v45={int(bridge['v45']):04X} v56={int(bridge['v56']):04X}"
    )
    print(
        f"  recovered s1={int(bridge['s1']):04X} s2={int(bridge['s2']):04X}"
        f" s5={int(bridge['s5']):04X}"
    )
    print(
        f"  true      s1={int(state0[0]):04X} s2={int(state0[1]):04X}"
        f" s5={int(state0[4]):04X}"
    )
    print("  reduced solver without next s4:")
    for idx, model in enumerate(free_family["models"], start=1):
        print(
            f"    model#{idx}: s1={int(model['s1']):04X} s2={int(model['s2']):04X}"
            f" s4={int(model['s4']):04X} s4_next={int(model['s4_next']):04X}"
        )
    print("  reduced solver with next s4 fixed:")
    for idx, model in enumerate(fixed_family["models"], start=1):
        print(
            f"    model#{idx}: s1={int(model['s1']):04X} s2={int(model['s2']):04X}"
            f" s4={int(model['s4']):04X} s4_next={int(model['s4_next']):04X}"
        )
    print("  full-state recovery with fixed next s4:")
    print(f"    recovered={words_to_hex(recovered['full_state'])}")
    print(f"    true     ={words_to_hex(state0)}")


def run_core_demo(key_words: Sequence[int], iv_words: Sequence[int], prefix_words: Sequence[int], word_sequence: Sequence[int]) -> None:
    if len(word_sequence) < 2:
        raise ValueError("core-demo needs at least two plaintext words")

    ctx = ctx_after_prefix(key_words, iv_words, prefix_words)
    state0 = list(ctx["state"])
    assert isinstance(state0, list)
    pt0 = word_sequence[0] & 0xFFFF
    separ_encrypt_word(pt0, ctx, key_words)
    state1 = list(ctx["state"])
    lfsr1 = int(ctx["lfsr"])

    pt1 = word_sequence[1] & 0xFFFF
    separ_encrypt_word(pt1, ctx, key_words)
    state2 = list(ctx["state"])

    core0 = core5(state0)
    core1 = core5(state1)
    core2 = core5(state2)

    print("Exact 5-word core reconstruction demo")
    print(f"  iv={words_to_hex(iv_words)} prefix={words_to_hex(prefix_words)}")
    print(f"  pt0={pt0:04X} pt1={pt1:04X}")
    print(f"  core0={words_to_hex(core0)}")
    print(f"  core1={words_to_hex(core1)}")
    print(f"  core2={words_to_hex(core2)}")

    first = recover_round_state_from_core_pair(key_words, pt0, core0, core1)
    second = recover_round_state_from_core_pair(key_words, pt1, core1, core2)
    combined = recover_lfsr_from_core_triplet(key_words, pt0, pt1, core0, core1, core2)

    print("Round 0 reconstruction:")
    print_core_recovery(first, state0)
    print("Round 1 reconstruction:")
    print_core_recovery(second, state1)
    print("LFSR recovery from two adjacent core pairs:")
    print(f"  recovered lfsr step: {int(combined['lfsr1']):04X}")
    print(f"  true      lfsr step: {lfsr1:04X}")


def validate_lfsr_cancellation(
    key_words: Sequence[int],
    *,
    samples: int,
    rounds: int,
    seed: int,
) -> Tuple[int, int]:
    rng = random.Random(seed)
    checked = 0
    for _ in range(samples):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        left = separ_initial_ctx(key_words, iv_words)
        right = separ_initial_ctx(key_words, iv_words)

        for _ in range(rounds):
            pt_left = rng.randrange(0x10000)
            pt_right = rng.randrange(0x10000)
            left_before = list(left["state"])
            right_before = list(right["state"])
            left_trace = round_trace_from_state(left_before, pt_left, key_words)
            right_trace = round_trace_from_state(right_before, pt_right, key_words)
            separ_encrypt_word(pt_left, left, key_words)
            separ_encrypt_word(pt_right, right, key_words)

            delta_before = differential_state(left_before, right_before)
            delta_after = differential_state(left["state"], right["state"])

            delta_v12 = (int(right_trace["v12"]) - int(left_trace["v12"])) & 0xFFFF
            delta_v23 = (int(right_trace["v23"]) - int(left_trace["v23"])) & 0xFFFF
            delta_v34 = (int(right_trace["v34"]) - int(left_trace["v34"])) & 0xFFFF
            delta_v45 = (int(right_trace["v45"]) - int(left_trace["v45"])) & 0xFFFF
            delta_v56 = (int(right_trace["v56"]) - int(left_trace["v56"])) & 0xFFFF
            delta_v67 = (int(right_trace["v67"]) - int(left_trace["v67"])) & 0xFFFF
            delta_v78 = (int(right_trace["v78"]) - int(left_trace["v78"])) & 0xFFFF

            predicted = [0] * 8
            predicted[1] = (delta_before[1] + delta_v12 + delta_v56 + delta_before[5]) & 0xFFFF
            predicted[2] = (delta_before[2] + delta_v23 + delta_v34 + delta_before[3] + delta_before[0]) & 0xFFFF
            predicted[3] = (delta_before[3] + delta_v12 + delta_v45 + delta_before[7]) & 0xFFFF
            predicted[4] = (delta_before[4] + delta_v23) & 0xFFFF
            predicted[5] = (delta_before[5] + delta_v12 + delta_v45 + delta_before[6]) & 0xFFFF
            predicted[6] = (delta_before[6] + delta_v23 + delta_v67) & 0xFFFF
            predicted[7] = (delta_before[7] + delta_v45) & 0xFFFF
            predicted[0] = (delta_before[0] + delta_before[4] + delta_v34 + (2 * delta_v23) + delta_v78) & 0xFFFF

            if predicted != delta_after:
                raise AssertionError("same-reset differential recurrence did not match the exact LFSR-free formula")
            checked += 1
    return checked, samples


def validate_suffix_bridge_recovery(
    key_words: Sequence[int],
    *,
    samples: int,
    rounds: int,
    seed: int,
) -> Tuple[int, int, int]:
    rng = random.Random(seed)
    bridge_checks = 0
    free_solver_checks = 0
    fixed_solver_checks = 0
    for _ in range(samples):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        prefix_len = rng.randrange(0, 3)
        prefix_words = [rng.randrange(0x10000) for _ in range(prefix_len)]
        ctx = ctx_after_prefix(key_words, iv_words, prefix_words)

        for _ in range(rounds):
            state0 = list(ctx["state"])
            assert isinstance(state0, list)
            pt = rng.randrange(0x10000)
            ct = separ_encrypt_word(pt, ctx, key_words)
            state1 = list(ctx["state"])

            bridge = recover_round_suffix_bridge(key_words, pt, ct, suffix4(state0), suffix3(state1))
            if not bool(bridge["s5_consistent"]):
                raise AssertionError("suffix-bridge failed to recover s5 exactly")
            if int(bridge["s1"]) != (int(state0[0]) & 0xFFFF):
                raise AssertionError("suffix-bridge failed to recover s1 exactly")
            if int(bridge["s2"]) != (int(state0[1]) & 0xFFFF):
                raise AssertionError("suffix-bridge failed to recover s2 exactly")

            free_family = solve_suffix_bridge_family(bridge, max_models=2)
            fixed_family = solve_suffix_bridge_family(bridge, next_s4=state1[3], max_models=2)
            if len(free_family["models"]) < 2:
                raise AssertionError("reduced suffix-bridge family should retain one free 16-bit word without next s4")
            if len(fixed_family["models"]) != 1:
                raise AssertionError("reduced suffix-bridge family should be unique once next s4 is fixed")

            recovered = recover_round_state_from_suffix_bridge_and_next_s4(key_words, bridge, state1[3])
            full_state = recovered["full_state"]
            assert isinstance(full_state, list)
            if [int(x) & 0xFFFF for x in full_state] != [int(x) & 0xFFFF for x in state0]:
                raise AssertionError("suffix-bridge + next s4 failed to recover the full round state")

            bridge_checks += 1
            free_solver_checks += 1
            fixed_solver_checks += 1

    return bridge_checks, free_solver_checks, fixed_solver_checks


def validate_core_recovery(
    key_words: Sequence[int],
    *,
    samples: int,
    rounds: int,
    seed: int,
) -> Tuple[int, int]:
    rng = random.Random(seed)
    pair_checks = 0
    lfsr_checks = 0
    for _ in range(samples):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        ctx = separ_initial_ctx(key_words, iv_words)

        states = [list(ctx["state"])]
        lfsrs = [int(ctx["lfsr"])]
        words = []
        for _ in range(rounds):
            pt = rng.randrange(0x10000)
            words.append(pt)
            separ_encrypt_word(pt, ctx, key_words)
            states.append(list(ctx["state"]))
            lfsrs.append(int(ctx["lfsr"]))

        for idx in range(rounds):
            recovered = recover_round_state_from_core_pair(
                key_words,
                words[idx],
                core5(states[idx]),
                core5(states[idx + 1]),
            )
            full_state = recovered["full_state"]
            assert isinstance(full_state, list)
            if full_state != states[idx]:
                raise AssertionError("5-word core pair failed to recover the full round state")
            pair_checks += 1

        for idx in range(rounds - 1):
            recovered = recover_lfsr_from_core_triplet(
                key_words,
                words[idx],
                words[idx + 1],
                core5(states[idx]),
                core5(states[idx + 1]),
                core5(states[idx + 2]),
            )
            if int(recovered["lfsr1"]) != lfsrs[idx + 1]:
                raise AssertionError("adjacent core pairs failed to recover the stepped LFSR word")
            lfsr_checks += 1

    return pair_checks, lfsr_checks


def validate_outer4_recovery(
    key_words: Sequence[int],
    *,
    samples: int,
    rounds: int,
    seed: int,
) -> Tuple[int, int]:
    rng = random.Random(seed)
    pair_checks = 0
    lfsr_checks = 0
    for _ in range(samples):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        ctx = separ_initial_ctx(key_words, iv_words)

        states = [list(ctx["state"])]
        lfsrs = [int(ctx["lfsr"])]
        words = []
        for _ in range(rounds):
            pt = rng.randrange(0x10000)
            words.append(pt)
            separ_encrypt_word(pt, ctx, key_words)
            states.append(list(ctx["state"]))
            lfsrs.append(int(ctx["lfsr"]))

        for idx in range(rounds):
            recovered = recover_round_state_from_outer4_pair(
                key_words,
                words[idx],
                outer4(states[idx]),
                outer4(states[idx + 1]),
            )
            full_state = recovered["full_state"]
            assert isinstance(full_state, list)
            if full_state != states[idx]:
                raise AssertionError("4-word outer-even pair failed to recover the full round state")
            pair_checks += 1

        for idx in range(rounds - 1):
            recovered = recover_lfsr_from_outer4_triplet(
                key_words,
                words[idx],
                words[idx + 1],
                outer4(states[idx]),
                outer4(states[idx + 1]),
                outer4(states[idx + 2]),
            )
            if int(recovered["lfsr1"]) != lfsrs[idx + 1]:
                raise AssertionError("adjacent outer-even pairs failed to recover the stepped LFSR word")
            lfsr_checks += 1

    return pair_checks, lfsr_checks


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Focused exact right-recursive ladder attack for the broken SEPAR implementation."
    )
    parser.add_argument(
        "--mode",
        choices=[
            "demo",
            "scan",
            "left-scan",
            "search",
            "left-search",
            "support-collapse-scan",
            "low-byte-scan",
            "high-byte-scan",
            "recursive-pair-scan",
            "outer4-demo",
            "outer4-validate",
            "suffix-bridge-demo",
            "suffix-bridge-validate",
            "core-demo",
            "core-validate",
            "transport-validate",
            "transport-pair-scan",
            "trail-validate",
            "iv-pair-search",
            "iv-eval",
            "iv-search",
            "iv-local-search",
            "outer-bootstrap",
            "k8-pivot",
            "reduced-pivot",
            "recursive-public",
            "context-search",
            "stage1-finish",
            "state-byte-scan",
            "state-word-scan",
            "candidate-verify",
        ],
        default="demo",
    )
    parser.add_argument("--key", help="optional 64-hex full key; defaults to the implementation key")
    parser.add_argument("--iv", help="32-hex IV for scan mode")
    parser.add_argument("--target-right", type=int, help="visible right stage K_i to attack")
    parser.add_argument("--prefix", default="", help="comma-separated plaintext prefix words in hex")
    parser.add_argument("--iv7-family", default="", help="comma-separated IV[7] values for context-search mode")
    parser.add_argument("--prefix-family", default="", help="comma-separated one-word prefix values for context-search mode")
    parser.add_argument("--words", default="1234,5678", help="comma-separated plaintext words for core demo / validation")
    parser.add_argument("--known-right-states", default="", help="comma-separated stage=word guesses for already known outer right states")
    parser.add_argument("--scan-stage", type=int, help="state word s_i to scan in state-byte-scan mode")
    parser.add_argument("--scan-part", choices=["low", "upper"], default="low")
    parser.add_argument("--fixed-other-byte", help="fixed other byte in hex for state-byte-scan mode")
    parser.add_argument("--fixed-low-byte", help="fixed low byte in hex for high-byte-scan mode")
    parser.add_argument("--iv-list", default="", help="comma-separated list of 32-hex IVs for candidate verification")
    parser.add_argument("--candidate-pair", help="candidate key pair as AAAA,BBBB for candidate-verify mode")
    parser.add_argument("--candidate-next-pair", help="candidate next-stage key pair as AAAA,BBBB for high-byte-scan mode")
    parser.add_argument("--candidate-stage", type=int, help="candidate right stage K_i for candidate-verify mode")
    parser.add_argument("--rows", default="00,55,AA,FF", help="comma-separated row bytes for support-collapse-scan mode")
    parser.add_argument("--delta", help="16-bit delta for trail validation / IV-pair search (hex)")
    parser.add_argument("--probe-words", default="0000,1111,2222", help="comma-separated probe plaintext words for IV-pair search")
    parser.add_argument("--score-his", default="00", help="comma-separated upper-byte values for chosen-IV row scoring")
    parser.add_argument("--pair-patterns", default="", help="comma-separated built-in pair-pattern names for iv-eval / iv-search")
    parser.add_argument("--start-ivs", default="", help="comma-separated 32-hex IV seeds for iv-local-search mode")
    parser.add_argument("--objective", choices=["chosen", "enc", "dec", "pair"], default="chosen", help="objective for iv-local-search mode")
    parser.add_argument("--truth-check", action="store_true", help="annotate IV-pair fingerprint matches with hidden-state truth data")
    parser.add_argument("--empty-prefix-only", action="store_true", help="scan only epsilon-prefix contexts in context-search mode")
    parser.add_argument("--no-empty-prefix", action="store_true", help="exclude epsilon-prefix contexts in context-search mode")
    parser.add_argument("--diffs", default=",".join(f"{d:04x}" for d in DEFAULT_DIFFS))
    parser.add_argument("--prefilter-diffs", default="", help="comma-separated diffs for cheap outer-bootstrap pair prefilter")
    parser.add_argument("--sample-step", type=int, default=1024)
    parser.add_argument("--sample-count", type=int, default=64)
    parser.add_argument("--class-limit", type=int, default=128, help="0 means exhaustive")
    parser.add_argument("--class-seed", type=int, default=1)
    parser.add_argument("--row-step", type=int, default=16, help="row stride for exact branchless high-byte scans")
    parser.add_argument("--exact", action="store_true")
    parser.add_argument("--exact-top", type=int, default=4)
    parser.add_argument("--sampled-top", type=int, default=8, help="sampled shortlist size for state-word / candidate verification")
    parser.add_argument("--top", type=int, default=8, help="number of ranked entries to print for exact scans")
    parser.add_argument("--outer-iv-beam", type=int, default=4, help="number of weak IVs refined in outer-bootstrap mode")
    parser.add_argument("--signature-beam", type=int, default=32, help="number of public K8 lane signatures kept in outer-bootstrap mode")
    parser.add_argument("--pair-beam", type=int, default=4, help="number of sampled K8 pair candidates kept per signature in outer-bootstrap mode")
    parser.add_argument("--cycle-top", type=int, default=4, help="number of top projected cycles to print / keep")
    parser.add_argument("--overall-top", type=int, default=32, help="number of projected cycles explored in k8-pivot mode")
    parser.add_argument("--low-beam", type=int, default=1, help="number of low-byte candidates kept in recursive-public mode")
    parser.add_argument("--beam", type=int, default=4, help="beam width for iv-local-search mode")
    parser.add_argument("--children", type=int, default=32, help="children per beam item for iv-local-search mode")
    parser.add_argument("--trials", type=int, default=8)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--analyze-best", type=int, default=3)
    parser.add_argument("--rounds", type=int, default=3, help="round count for core validation")
    parser.add_argument("--samples", type=int, default=16, help="sample count for core validation")
    args = parser.parse_args()

    key_words = parse_full_key_hex(args.key) if args.key else list(DEFAULT_KEY)
    prefix_words = parse_word_list(args.prefix)
    word_sequence = parse_word_list(args.words)
    known_right_states = parse_stage_word_map(args.known_right_states)
    diffs = parse_word_list(args.diffs)
    prefilter_diffs = parse_word_list(args.prefilter_diffs) if args.prefilter_diffs.strip() else list(diffs)
    sample_x = list(range(0, 0x10000, max(1, args.sample_step)))[: max(1, args.sample_count)]
    class_limit = None if args.class_limit <= 0 else args.class_limit
    hi_values = parse_hi_bytes(args.score_his)
    rows = [value & 0xFF for value in parse_word_list(args.rows)]

    if args.mode == "demo":
        run_demo(key_words, prefix_words, diffs, sample_x, class_limit, args.class_seed, max(0, args.exact_top))
        return

    if args.mode == "low-byte-scan":
        if args.target_right is None:
            raise SystemExit("--target-right is required in low-byte-scan mode")
        iv_words = parse_full_iv_hex(args.iv) if args.iv else parse_full_iv_hex(KNOWN_STAGE_IVS[args.target_right])
        candidate_pair = parse_key_pair(args.candidate_pair) if args.candidate_pair else stage_key_pair(key_words, args.target_right)
        result = exact_stage_low_byte_scan(
            key_words,
            iv_words,
            prefix_words,
            args.target_right,
            candidate_pair,
            known_right_states,
            topn=max(1, args.top),
        )
        print_low_byte_scan(result)
        return

    if args.mode == "high-byte-scan":
        if args.target_right is None:
            raise SystemExit("--target-right is required in high-byte-scan mode")
        if args.target_right <= 1:
            raise SystemExit("--target-right must be in 2..8 for high-byte-scan mode")
        iv_words = parse_full_iv_hex(args.iv) if args.iv else parse_full_iv_hex(KNOWN_STAGE_IVS[args.target_right])
        candidate_pair = parse_key_pair(args.candidate_pair) if args.candidate_pair else stage_key_pair(key_words, args.target_right)
        if args.fixed_low_byte:
            fixed_low = int(args.fixed_low_byte, 16) & 0xFF
        else:
            fixed_low = None
        if args.candidate_next_pair:
            candidate_next_pairs = [parse_key_pair(args.candidate_next_pair)]
        else:
            true_next_pair = stage_key_pair(key_words, args.target_right - 1)
            sampled_pairs, _, _, _ = lane_class_candidates(true_next_pair, args.target_right - 1, class_limit, args.class_seed)
            candidate_next_pairs = sampled_pairs
        result = exact_stage_high_byte_scan(
            key_words,
            iv_words,
            prefix_words,
            args.target_right,
            candidate_pair,
            known_right_states,
            candidate_next_pairs,
            fixed_low=fixed_low,
            row_step=max(1, args.row_step),
            topn=max(1, args.top),
        )
        print_high_byte_scan(result)
        return

    if args.mode == "recursive-pair-scan":
        if args.target_right is None:
            raise SystemExit("--target-right is required in recursive-pair-scan mode")
        if args.target_right <= 2:
            raise SystemExit("--target-right must be in 3..8 for recursive-pair-scan mode")
        iv_words = parse_full_iv_hex(args.iv) if args.iv else parse_full_iv_hex(KNOWN_STAGE_IVS[args.target_right])
        candidate_pair = parse_key_pair(args.candidate_pair) if args.candidate_pair else stage_key_pair(key_words, args.target_right)
        fixed_low = int(args.fixed_low_byte, 16) & 0xFF if args.fixed_low_byte else None
        if args.candidate_next_pair:
            candidate_next_pairs = [parse_key_pair(args.candidate_next_pair)]
        else:
            true_next_pair = stage_key_pair(key_words, args.target_right - 1)
            sampled_pairs, _, _, _ = lane_class_candidates(true_next_pair, args.target_right - 1, class_limit, args.class_seed)
            candidate_next_pairs = sampled_pairs
        result = recursive_pair_scan(
            key_words,
            iv_words,
            prefix_words,
            args.target_right,
            candidate_pair,
            known_right_states,
            candidate_next_pairs,
            fixed_low=fixed_low,
            row_step=max(1, args.row_step),
            topn=max(1, args.top),
        )
        print_recursive_pair_scan(result)
        return

    if args.mode == "support-collapse-scan":
        if args.target_right is None:
            raise SystemExit("--target-right is required in support-collapse-scan mode")
        iv_words = parse_full_iv_hex(args.iv) if args.iv else parse_full_iv_hex(KNOWN_STAGE_IVS[args.target_right])
        if args.candidate_pair:
            candidate_pairs = [parse_key_pair(args.candidate_pair)]
        else:
            true_pair = stage_key_pair(key_words, args.target_right)
            sampled_pairs, _, _, _ = lane_class_candidates(true_pair, args.target_right, class_limit, args.class_seed)
            candidate_pairs = sampled_pairs
        result = exact_stage_support_collapse_scan(
            key_words,
            iv_words,
            prefix_words,
            args.target_right,
            known_right_states,
            candidate_pairs,
            rows=rows,
            topn=max(1, args.top),
        )
        print_support_collapse_scan(result)
        return

    if args.mode == "outer4-demo":
        iv_words = parse_full_iv_hex(args.iv) if args.iv else parse_full_iv_hex(KNOWN_STAGE_IVS[1])
        run_outer4_demo(key_words, iv_words, prefix_words, word_sequence)
        return

    if args.mode == "outer4-validate":
        diff_checks, diff_samples = validate_lfsr_cancellation(
            key_words,
            samples=max(1, args.samples),
            rounds=max(1, args.rounds),
            seed=args.seed,
        )
        pair_checks, lfsr_checks = validate_outer4_recovery(
            key_words,
            samples=max(1, args.samples),
            rounds=max(2, args.rounds),
            seed=args.seed,
        )
        print("Outer-even core/LFSR exact validation")
        print(f"  same-reset differential checks passed: {diff_checks} over {diff_samples} IV samples")
        print(f"  outer-even pair full-state recoveries passed: {pair_checks}")
        print(f"  adjacent outer-even pair LFSR recoveries passed: {lfsr_checks}")
        return

    if args.mode == "suffix-bridge-demo":
        iv_words = parse_full_iv_hex(args.iv) if args.iv else parse_full_iv_hex(KNOWN_STAGE_IVS[5])
        run_suffix_bridge_demo(key_words, iv_words, prefix_words, word_sequence)
        return

    if args.mode == "suffix-bridge-validate":
        bridge_checks, free_solver_checks, fixed_solver_checks = validate_suffix_bridge_recovery(
            key_words,
            samples=max(1, args.samples),
            rounds=max(1, args.rounds),
            seed=args.seed,
        )
        print("Suffix-bridge exact validation")
        print(f"  suffix-bridge recoveries passed: {bridge_checks}")
        print(f"  reduced-family free-word solver checks passed: {free_solver_checks}")
        print(f"  reduced-family unique-finish solver checks passed: {fixed_solver_checks}")
        return

    if args.mode == "core-demo":
        iv_words = parse_full_iv_hex(args.iv) if args.iv else parse_full_iv_hex(KNOWN_STAGE_IVS[1])
        run_core_demo(key_words, iv_words, prefix_words, word_sequence)
        return

    if args.mode == "core-validate":
        diff_checks, diff_samples = validate_lfsr_cancellation(
            key_words,
            samples=max(1, args.samples),
            rounds=max(1, args.rounds),
            seed=args.seed,
        )
        pair_checks, lfsr_checks = validate_core_recovery(
            key_words,
            samples=max(1, args.samples),
            rounds=max(2, args.rounds),
            seed=args.seed,
        )
        print("Core/LFSR exact validation")
        print(f"  same-reset differential checks passed: {diff_checks} over {diff_samples} IV samples")
        print(f"  core-pair full-state recoveries passed: {pair_checks}")
        print(f"  adjacent core-pair LFSR recoveries passed: {lfsr_checks}")
        return

    if args.mode == "transport-validate":
        rows = validate_transport_law(
            key_words,
            samples=max(1, args.samples),
            seed=args.seed,
            prefix_words=prefix_words,
        )
        print_transport_validation(rows)
        return

    if args.mode == "transport-pair-scan":
        if args.target_right is None:
            raise SystemExit("--target-right is required in transport-pair-scan mode")
        if args.target_right < 1 or args.target_right > 7:
            raise SystemExit("--target-right must be in 1..7 for transport-pair-scan mode")
        iv_words = parse_full_iv_hex(args.iv) if args.iv else parse_full_iv_hex(KNOWN_STAGE_IVS[max(1, args.target_right)])
        if args.candidate_pair:
            candidate_pairs = [parse_key_pair(args.candidate_pair)]
        else:
            true_pair = stage_key_pair(key_words, args.target_right)
            sampled_pairs, _, _, _ = lane_class_candidates(true_pair, args.target_right, class_limit, args.class_seed)
            candidate_pairs = sampled_pairs
        result = transport_pair_scan(
            key_words,
            iv_words,
            prefix_words,
            args.target_right,
            candidate_pairs,
            topn=max(1, args.top),
        )
        print_transport_pair_scan(result)
        return

    if args.mode == "trail-validate":
        delta = int(args.delta, 16) & 0xFFFF if args.delta else 0x8000
        result = validate_exact_related_state_family(
            key_words,
            delta=delta,
            samples=max(1, args.samples),
            seed=args.seed,
        )
        print_related_state_validation(result)
        return

    if args.mode == "iv-pair-search":
        delta = int(args.delta, 16) & 0xFFFF if args.delta else 0x8000
        probe_words = parse_word_list(args.probe_words)
        result = search_related_iv_pairs_by_fingerprint(
            key_words,
            delta=delta,
            trials=max(1, args.trials),
            seed=args.seed,
            probe_words=probe_words,
            truth_check=args.truth_check,
        )
        print_related_iv_search(result)
        return

    if args.mode == "iv-eval":
        if args.iv is None:
            raise SystemExit("--iv is required in iv-eval mode")
        delta = int(args.delta, 16) & 0xFFFF if args.delta else 0x8000
        pair_probe_words = parse_word_list(args.probe_words)
        pair_patterns = parse_pair_pattern_names(args.pair_patterns, delta)
        iv_words = parse_full_iv_hex(args.iv)
        result = evaluate_public_iv_candidate(
            key_words,
            iv_words,
            hi_values=hi_values,
            diffs=diffs,
            sample_x=sample_x,
            delta_word=delta,
            pair_probe_words=pair_probe_words,
            pair_patterns=pair_patterns,
            truth_eval=args.truth_check,
        )
        print_public_iv_candidate(result)
        return

    if args.mode == "iv-search":
        delta = int(args.delta, 16) & 0xFFFF if args.delta else 0x8000
        pair_probe_words = parse_word_list(args.probe_words)
        pair_patterns = parse_pair_pattern_names(args.pair_patterns, delta)
        results = search_public_iv_candidates(
            key_words,
            trials=max(1, args.trials),
            seed=args.seed,
            hi_values=hi_values,
            diffs=diffs,
            sample_x=sample_x,
            delta_word=delta,
            pair_probe_words=pair_probe_words,
            pair_patterns=pair_patterns,
            truth_eval=args.truth_check,
        )
        ranked_chosen = sorted(results, key=public_iv_sort_key_chosen, reverse=True)
        ranked_pair = sorted(results, key=public_iv_sort_key_pair, reverse=True)
        print("Best public IV candidates by chosen-IV weakness")
        for result in ranked_chosen[: max(1, args.analyze_best)]:
            print_public_iv_candidate(result)
            print()
        print("Best public IV candidates by pair-aware cancellation")
        for result in ranked_pair[: max(1, args.analyze_best)]:
            print_public_iv_candidate(result)
            print()
        return

    if args.mode == "iv-local-search":
        delta = int(args.delta, 16) & 0xFFFF if args.delta else 0x8000
        pair_probe_words = parse_word_list(args.probe_words)
        pair_patterns = parse_pair_pattern_names(args.pair_patterns, delta)
        starts = parse_iv_list(args.start_ivs) if args.start_ivs.strip() else []
        if args.iv:
            starts.append(parse_full_iv_hex(args.iv))
        if not starts:
            starts = [parse_full_iv_hex(known) for known in sorted(set(KNOWN_STAGE_IVS.values()))]
        results = local_search_public_iv_candidates(
            key_words,
            starts=starts,
            rounds=max(1, args.rounds),
            beam=max(1, args.beam),
            children=max(1, args.children),
            seed=args.seed,
            objective=args.objective,
            hi_values=hi_values,
            diffs=diffs,
            sample_x=sample_x,
            delta_word=delta,
            pair_probe_words=pair_probe_words,
            pair_patterns=pair_patterns,
            truth_eval=args.truth_check,
        )
        for result in results[: max(1, args.analyze_best)]:
            print_public_iv_candidate(result)
            print()
        return

    if args.mode == "outer-bootstrap":
        if args.iv is not None:
            iv_candidates = [
                {
                    "iv": parse_full_iv_hex(args.iv),
                }
            ]
            ctx = ctx_after_prefix(key_words, iv_candidates[0]["iv"], prefix_words)
            table = next_word_table(ctx, key_words)
            state = ctx["state"]
            assert isinstance(state, list)
            iv_candidates[0]["table"] = table
            iv_candidates[0]["state"] = list(state)
            iv_candidates[0]["summary"] = outer_bootstrap_iv_summary(
                ctx,
                table,
                key_words,
                hi_values,
                diffs,
                sample_x,
                truth_eval=args.truth_check,
            )
        else:
            search_results = search_outer_bootstrap_contexts(
                key_words,
                prefix_words,
                trials=max(1, args.trials),
                seed=args.seed,
                hi_values=hi_values,
                diffs=diffs,
                sample_x=sample_x,
                truth_eval=args.truth_check,
            )
            iv_candidates = sorted(search_results, key=outer_bootstrap_sort_key)[: max(1, args.outer_iv_beam)]

        per_iv_results = []
        for idx, iv_item in enumerate(iv_candidates):
            result = outer_bootstrap_from_iv(
                iv_item["table"],
                key_words,
                diffs,
                prefilter_diffs,
                sample_x,
                max(1, args.signature_beam),
                class_limit,
                args.class_seed + idx,
                max(1, args.pair_beam),
                max(1, args.exact_top),
                truth_eval=args.truth_check,
            )
            per_iv_results.append(result)
            print_outer_bootstrap_iv(iv_item, result)
            print()

        aggregate = aggregate_outer_bootstrap(
            iv_candidates,
            per_iv_results,
            key_words,
            diffs,
            truth_eval=args.truth_check,
        )
        print_outer_bootstrap_aggregate(aggregate)
        return

    if args.mode == "k8-pivot":
        iv_words = parse_full_iv_hex(args.iv) if args.iv else ([0] * 8)
        set_progress_enabled(True)
        try:
            result = k8_projected_cycle_bootstrap(
                key_words,
                iv_words,
                prefix_words,
                diffs,
                cycle_top=max(1, args.cycle_top),
                overall_top=max(1, args.overall_top),
                truth_eval=args.truth_check,
            )
        finally:
            set_progress_enabled(False)
        print_k8_pivot(result)
        return

    if args.mode == "reduced-pivot":
        if args.target_right is None:
            raise SystemExit("--target-right is required in reduced-pivot mode")
        if args.target_right < 1 or args.target_right > 7:
            raise SystemExit("--target-right must be in 1..7 for reduced-pivot mode")
        iv_words = parse_full_iv_hex(args.iv) if args.iv else parse_full_iv_hex(KNOWN_STAGE_IVS[args.target_right])
        if known_right_states:
            info(
                "using supplied right-stage states "
                + ", ".join(f"s{stage}={word:04X}" for stage, word in sorted(known_right_states.items()))
                + " (cheating unless independently recovered)"
            )
        set_progress_enabled(True)
        try:
            result = reduced_projected_cycle_scan(
                key_words,
                iv_words,
                prefix_words,
                args.target_right,
                known_right_states,
                diffs,
                cycle_top=max(1, args.cycle_top),
                overall_top=max(1, args.overall_top),
                truth_eval=args.truth_check,
            )
        finally:
            set_progress_enabled(False)
        print_reduced_projected_cycle_scan(result)
        return

    if args.mode == "recursive-public":
        if args.target_right is None:
            raise SystemExit("--target-right is required in recursive-public mode")
        if args.target_right < 1 or args.target_right > 7:
            raise SystemExit("--target-right must be in 1..7 for recursive-public mode")
        iv_words = parse_full_iv_hex(args.iv) if args.iv else parse_full_iv_hex(KNOWN_STAGE_IVS[args.target_right])
        known_outer_keys: Dict[int, Tuple[int, int]] = {}
        for stage_idx in range(args.target_right + 1, 9):
            known_outer_keys[stage_idx] = stage_key_pair(key_words, stage_idx)
        info(
            "injecting true outer keys "
            + ", ".join(f"K{stage_idx}" for stage_idx in sorted(known_outer_keys))
            + " (cheating)"
        )
        set_progress_enabled(True)
        try:
            result = recursive_public_context_recovery(
                key_words,
                iv_words,
                prefix_words,
                known_outer_keys,
                args.target_right,
                diffs,
                low_beam=max(1, args.low_beam),
                cycle_beam=max(1, args.cycle_top),
            )
        finally:
            set_progress_enabled(False)
        print_recursive_public_context_recovery(result)
        return

    if args.mode == "context-search":
        if args.target_right is None:
            raise SystemExit("--target-right is required in context-search mode")
        if args.target_right < 1 or args.target_right > 8:
            raise SystemExit("--target-right must be in 1..8 for context-search mode")
        iv7_family = parse_word_list(args.iv7_family) if args.iv7_family.strip() else list(RECURSIVE_WEAK_IV7_FAMILY)
        prefix_family = parse_word_list(args.prefix_family) if args.prefix_family.strip() else list(RECURSIVE_WEAK_PREFIX_FAMILY)
        result = recursive_context_search(
            key_words,
            args.target_right,
            diffs,
            iv7_values=iv7_family,
            prefix_values=prefix_family,
            include_empty_prefix=(not args.no_empty_prefix) or args.empty_prefix_only,
            empty_only=args.empty_prefix_only,
            known_outer_states=known_right_states,
            oracle_reduced=args.truth_check,
            cycle_top=max(1, args.cycle_top),
            overall_top=max(1, args.overall_top),
            low_beam=max(1, args.low_beam),
            topn=max(1, args.top),
        )
        print_recursive_context_search(result)
        return

    if args.mode == "stage1-finish":
        if args.iv is None:
            raise SystemExit("--iv is required in stage1-finish mode")
        if not args.candidate_pair:
            raise SystemExit("--candidate-pair must be the known K2 pair in stage1-finish mode")
        if any(stage not in known_right_states for stage in range(2, 9)):
            raise SystemExit("--known-right-states must include 2..8 in stage1-finish mode")
        info("using supplied K2 and states s2..s8 (cheating unless independently recovered)")
        iv_words = parse_full_iv_hex(args.iv)
        result = stage1_finish_scan(
            key_words,
            iv_words,
            prefix_words,
            parse_key_pair(args.candidate_pair),
            known_right_states,
        )
        print_stage1_finish_scan(result)
        return

    if args.mode == "state-byte-scan":
        if args.iv is None:
            raise SystemExit("--iv is required in state-byte-scan mode")
        if args.scan_stage is None:
            raise SystemExit("--scan-stage is required in state-byte-scan mode")
        iv_words = parse_full_iv_hex(args.iv)
        if args.fixed_other_byte:
            fixed_other_byte = int(args.fixed_other_byte, 16) & 0xFF
        else:
            ctx = ctx_after_prefix(key_words, iv_words, prefix_words)
            state = ctx["state"]
            assert isinstance(state, list)
            word = int(state[args.scan_stage - 1]) & 0xFFFF
            fixed_other_byte = (word >> 8) & 0xFF if args.scan_part == "low" else (word & 0xFF)
        result = public_right_state_byte_scan(
            key_words,
            iv_words,
            prefix_words,
            args.scan_stage,
            known_right_states,
            part=args.scan_part,
            fixed_other_byte=fixed_other_byte,
            diffs=diffs,
            sample_x=sample_x,
            exact_top=max(0, args.exact_top),
        )
        print_public_state_scan(result)
        return

    if args.mode == "state-word-scan":
        if args.iv is None:
            raise SystemExit("--iv is required in state-word-scan mode")
        if args.scan_stage is None:
            raise SystemExit("--scan-stage is required in state-word-scan mode")
        iv_words = parse_full_iv_hex(args.iv)
        if args.scan_stage == 8 and not known_right_states:
            result = outer_s8_word_scan(
                key_words,
                iv_words,
                prefix_words,
                stage_key_pair(key_words, 7),
                diffs=diffs,
                sample_x=sample_x,
                sampled_top=max(1, args.sampled_top),
                exact_top=max(0, args.exact_top),
            )
        else:
            result = public_right_state_word_scan(
                key_words,
                iv_words,
                prefix_words,
                args.scan_stage,
                known_right_states,
                diffs=diffs,
                sample_x=sample_x,
                sampled_top=max(1, args.sampled_top),
                exact_top=max(0, args.exact_top),
            )
        print_public_state_word_scan(result)
        return

    if args.mode == "candidate-verify":
        if args.candidate_stage is None:
            raise SystemExit("--candidate-stage is required in candidate-verify mode")
        if args.candidate_pair is None:
            raise SystemExit("--candidate-pair is required in candidate-verify mode")
        iv_list = parse_iv_list(args.iv_list) if args.iv_list else ([parse_full_iv_hex(args.iv)] if args.iv else [])
        if not iv_list:
            raise SystemExit("--iv or --iv-list is required in candidate-verify mode")
        pair_words = parse_word_list(args.candidate_pair)
        if len(pair_words) != 2:
            raise SystemExit("--candidate-pair must contain exactly two 16-bit words")
        result = verify_right_stage_candidate(
            key_words,
            iv_list,
            prefix_words,
            args.candidate_stage,
            (pair_words[0], pair_words[1]),
            known_right_states,
            diffs=diffs,
            sample_x=sample_x,
            sampled_top=max(1, args.sampled_top),
            exact_top=max(0, args.exact_top),
        )
        print_candidate_verify(result)
        return

    if args.target_right is None:
        raise SystemExit("--target-right is required in scan/search/left-scan/left-search mode")

    if args.mode == "left-scan":
        if args.iv is None:
            raise SystemExit("--iv is required in left-scan mode")
        iv_words = parse_full_iv_hex(args.iv)
        result = injected_left_lane_scan(
            key_words,
            iv_words,
            prefix_words,
            args.target_right,
            diffs,
            sample_x,
            class_limit=class_limit,
            class_seed=args.class_seed,
            exact=args.exact,
            exact_top=max(0, args.exact_top),
        )
        print_left_scan(result)
        return

    if args.mode == "left-search":
        results = search_injected_left_contexts(
            key_words,
            prefix_words,
            args.target_right,
            diffs,
            sample_x,
            trials=max(1, args.trials),
            seed=args.seed,
            class_limit=class_limit,
            class_seed=args.class_seed,
        )
        for result in results[: max(1, args.analyze_best)]:
            print_left_scan(result)
            print()
        return

    if args.mode == "scan":
        if args.iv is None:
            raise SystemExit("--iv is required in scan mode")
        iv_words = parse_full_iv_hex(args.iv)
        result = injected_right_lane_scan(
            key_words,
            iv_words,
            prefix_words,
            args.target_right,
            diffs,
            sample_x,
            class_limit=class_limit,
            class_seed=args.class_seed,
            exact=args.exact,
            exact_top=max(0, args.exact_top),
        )
        print_scan(result)
        return

    results = search_injected_right_contexts(
        key_words,
        prefix_words,
        args.target_right,
        diffs,
        sample_x,
        trials=max(1, args.trials),
        seed=args.seed,
        class_limit=class_limit,
        class_seed=args.class_seed,
    )
    for result in results[: max(1, args.analyze_best)]:
        print_scan(result)
        print()


if __name__ == "__main__":
    main()
