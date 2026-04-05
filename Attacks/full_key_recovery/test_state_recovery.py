#!/usr/bin/env python3

import argparse
from collections import defaultdict
import random
from typing import Dict, List, Optional, Sequence, Tuple


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
DEFAULT_HI_VALUES = [0x00, 0x20, 0x40, 0x80, 0xA0, 0xFF]
DEFAULT_PREFILTER_DIFFS = list(range(0x0001, 0x0010))
_LANE_BUCKETS_BY_STAGE: Dict[int, Tuple[Dict[Tuple[int, int], List[int]], Dict[Tuple[int, int], List[int]]]] = {}


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


def parse_hex_word(token: str) -> int:
    token = token.strip().lower()
    if token.startswith("0x"):
        token = token[2:]
    if not token:
        raise ValueError("empty hex token")
    return int(token, 16) & 0xFFFF


def parse_word_list(text: str) -> List[int]:
    if not text:
        return []
    return [parse_hex_word(part) for part in text.split(",") if part.strip()]


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


def words_to_hex(words: Sequence[int]) -> str:
    return "".join(f"{word & 0xFFFF:04X}" for word in words)


def nibble2(x: int) -> int:
    return (x >> 8) & 0xF


def stage_key_pair(key_words: Sequence[int], stage_idx: int) -> Tuple[int, int]:
    base = 2 * (stage_idx - 1)
    return key_words[base], key_words[base + 1]


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


def parse_stage_list(text: str) -> List[int]:
    return sorted({int(part.strip(), 10) for part in text.split(",") if part.strip()})


def derive_visible_stage(peels: Sequence[int], side: str) -> int:
    if not peels:
        return 1 if side == "left" else 8
    if side == "left":
        return max(peels) + 1
    return min(peels) - 1


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


def ctx_after_prefix(key_words: Sequence[int], iv_words: Sequence[int], prefix_words: Sequence[int]):
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


def invert_table(table: Sequence[int]) -> List[int]:
    inv = [0] * 0x10000
    for x, y in enumerate(table):
        inv[y] = x
    return inv


def row_branch_score(table: Sequence[int], hi_values: Sequence[int]) -> float:
    total = 0
    for hi in hi_values:
        vals = set()
        base = (hi & 0xFF) << 8
        for lo in range(256):
            vals.add((table[base | lo] >> 8) & 0xFF)
        total += len(vals)
    return total / float(len(hi_values))


def sampled_diff_score(table: Sequence[int], diffs: Sequence[int], sample_x: Sequence[int]) -> int:
    total = 0
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in sample_x:
            out_diff = (table[(x + diff) & 0xFFFF] - table[x]) & 0xFFFF
            counts[out_diff] = counts.get(out_diff, 0) + 1
        total += max(counts.values())
    return total


def exact_diff_score(table: Sequence[int], diffs: Sequence[int]) -> int:
    total = 0
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in range(0x10000):
            out_diff = (table[(x + diff) & 0xFFFF] - table[x]) & 0xFFFF
            counts[out_diff] = counts.get(out_diff, 0) + 1
        total += max(counts.values())
    return total


def diff_score(table: Sequence[int], diffs: Sequence[int], sample_x: Sequence[int], *, exact: bool) -> int:
    if exact:
        return exact_diff_score(table, diffs)
    return sampled_diff_score(table, diffs, sample_x)


def candidate_pool(true_pair: Tuple[int, int], count: int, seed: int) -> List[Tuple[int, int]]:
    candidates = [true_pair, (0x0000, 0x0000), (0x1111, 0x2222), (0xBEEF, 0x1234)]
    seen = set(candidates)
    rng = random.Random(seed)
    while len(candidates) < count:
        pair = (rng.randrange(0x10000), rng.randrange(0x10000))
        if pair not in seen:
            seen.add(pair)
            candidates.append(pair)
    return candidates


def peel_right_exact(table: Sequence[int], stage_idx: int, pair: Tuple[int, int], state_word: int) -> List[int]:
    return [((dec_block(value, pair, stage_idx) - state_word) & 0xFFFF) for value in table]


def peel_left_exact(table: Sequence[int], stage_idx: int, pair: Tuple[int, int], state_word: int) -> List[int]:
    out = [0] * 0x10000
    for x, value in enumerate(table):
        u = enc_block((x + state_word) & 0xFFFF, pair, stage_idx)
        out[u] = value
    return out


def score_visible_right(
    table: Sequence[int],
    stage_idx: int,
    pair: Tuple[int, int],
    diffs: Sequence[int],
    sample_x: Sequence[int],
    *,
    exact: bool,
) -> int:
    peeled = [dec_block(value, pair, stage_idx) for value in table]
    return diff_score(peeled, diffs, sample_x, exact=exact)


def score_visible_left(
    table: Sequence[int],
    stage_idx: int,
    pair: Tuple[int, int],
    state_word: int,
    diffs: Sequence[int],
    sample_x: Sequence[int],
    *,
    exact: bool,
) -> int:
    inverse = invert_table(table)
    peeled = [enc_block((value + state_word) & 0xFFFF, pair, stage_idx) for value in inverse]
    return diff_score(peeled, diffs, sample_x, exact=exact)


def diff_positions(sample_x: Sequence[int], diffs: Sequence[int]) -> List[int]:
    positions = []
    seen = set()
    for x in sample_x:
        if x not in seen:
            seen.add(x)
            positions.append(x)
        for diff in diffs:
            y = (x + diff) & 0xFFFF
            if y not in seen:
                seen.add(y)
                positions.append(y)
    return positions


def sampled_diff_score_from_values(values: Dict[int, int], diffs: Sequence[int], sample_x: Sequence[int]) -> int:
    total = 0
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in sample_x:
            out_diff = (values[(x + diff) & 0xFFFF] - values[x]) & 0xFFFF
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
            out_diff = (values[(x + diff) & 0xFFFF] - values[x]) & 0xFFFF
            projected = (out_diff >> shift) & mask
            counts[projected] = counts.get(projected, 0) + 1
        total += max(counts.values())
    return total


def sampled_row_branch_score_from_values(
    values: Dict[int, int],
    hi_values: Sequence[int],
    lo_values: Sequence[int],
) -> float:
    total = 0
    for hi in hi_values:
        seen = set()
        base = (hi & 0xFF) << 8
        for lo in lo_values:
            seen.add((values[base | (lo & 0xFF)] >> 8) & 0xFF)
        total += len(seen)
    return total / float(len(hi_values))


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


def score_visible_right_sampled_fast(
    table: Sequence[int],
    stage_idx: int,
    pair: Tuple[int, int],
    diffs: Sequence[int],
    sample_x: Sequence[int],
    positions: Sequence[int],
) -> int:
    values = {pos: dec_block(table[pos], pair, stage_idx) for pos in positions}
    return sampled_diff_score_from_values(values, diffs, sample_x)


def score_visible_left_sampled_fast(
    inverse: Sequence[int],
    stage_idx: int,
    pair: Tuple[int, int],
    state_word: int,
    diffs: Sequence[int],
    sample_x: Sequence[int],
    positions: Sequence[int],
) -> int:
    values = {pos: enc_block((inverse[pos] + state_word) & 0xFFFF, pair, stage_idx) for pos in positions}
    return sampled_diff_score_from_values(values, diffs, sample_x)


def rank_stage(
    table: Sequence[int],
    key_words: Sequence[int],
    stage_idx: int,
    side: str,
    state_word: Optional[int],
    diffs: Sequence[int],
    sample_x: Sequence[int],
    candidate_count: int,
    candidate_seed: int,
    *,
    exact: bool,
) -> Dict[str, object]:
    true_pair = stage_key_pair(key_words, stage_idx)
    candidates = candidate_pool(true_pair, candidate_count, candidate_seed)
    scores = []
    for pair in candidates:
        if side == "right":
            score = score_visible_right(table, stage_idx, pair, diffs, sample_x, exact=exact)
        else:
            assert state_word is not None
            score = score_visible_left(table, stage_idx, pair, state_word, diffs, sample_x, exact=exact)
        scores.append((score, pair))
    scores.sort(key=lambda item: (-item[0], item[1]))
    true_score = next(score for score, pair in scores if pair == true_pair)
    best_wrong = max(score for score, pair in scores if pair != true_pair)
    rank = 1 + sum(1 for score, pair in scores if score > true_score)
    return {
        "stage": stage_idx,
        "side": side,
        "true_pair": true_pair,
        "true_score": true_score,
        "best_wrong": best_wrong,
        "gap": true_score - best_wrong,
        "rank": rank,
        "top": scores[:5],
    }


def reduce_table_for_context(
    key_words: Sequence[int],
    iv_words: Sequence[int],
    prefix_words: Sequence[int],
    left_peels: Sequence[int],
    right_peels: Sequence[int],
) -> Tuple[List[int], Dict[str, List[int] | int]]:
    ctx = ctx_after_prefix(key_words, iv_words, prefix_words)
    table = next_word_table(ctx, key_words)
    state = ctx["state"]
    assert isinstance(state, list)

    for stage_idx in sorted(right_peels, reverse=True):
        table = peel_right_exact(table, stage_idx, stage_key_pair(key_words, stage_idx), state[stage_idx - 1])
    for stage_idx in sorted(left_peels):
        table = peel_left_exact(table, stage_idx, stage_key_pair(key_words, stage_idx), state[stage_idx - 1])
    return table, ctx


def lane_class_candidates(
    true_pair: Tuple[int, int],
    stage_idx: int,
    limit: Optional[int],
    seed: int,
) -> Tuple[List[Tuple[int, int]], int, bool, Tuple[int, int, int, int]]:
    left_buckets, right_buckets = lane_buckets_for_stage(stage_idx)
    signature = lane_pair_signature(true_pair, stage_idx)
    left_words = left_buckets[(signature[0], signature[1])]
    right_words = right_buckets[(signature[2], signature[3])]
    total_size = len(left_words) * len(right_words)

    if limit is None or limit <= 0 or limit >= total_size:
        candidates = [(k0, k1) for k0 in left_words for k1 in right_words]
        return candidates, total_size, True, signature

    rng = random.Random(seed)
    candidates = [true_pair]
    seen = {true_pair}
    while len(candidates) < limit:
        pair = (left_words[rng.randrange(len(left_words))], right_words[rng.randrange(len(right_words))])
        if pair not in seen:
            seen.add(pair)
            candidates.append(pair)
    return candidates, total_size, False, signature


def lane_class_scan(
    table: Sequence[int],
    key_words: Sequence[int],
    stage_idx: int,
    side: str,
    state_word: Optional[int],
    diffs: Sequence[int],
    prefilter_diffs: Sequence[int],
    sample_x: Sequence[int],
    class_limit: Optional[int],
    class_seed: int,
    exact_top: int,
) -> Dict[str, object]:
    true_pair = stage_key_pair(key_words, stage_idx)
    candidates, total_size, exhaustive, signature = lane_class_candidates(true_pair, stage_idx, class_limit, class_seed)
    positions = diff_positions(sample_x, sorted(set(diffs) | set(prefilter_diffs)))
    inverse = invert_table(table) if side == "left" else None

    prefilter_scores = []
    for pair in candidates:
        if side == "right":
            values = {pos: dec_block(table[pos], pair, stage_idx) for pos in positions}
        else:
            assert inverse is not None and state_word is not None
            values = {
                pos: enc_block((inverse[pos] + state_word) & 0xFFFF, pair, stage_idx)
                for pos in positions
            }
        prefilter_scores.append((prefilter_tuple_from_values(values, diffs, prefilter_diffs, sample_x), pair))

    prefilter_scores.sort(key=lambda item: (item[0], item[1]), reverse=True)
    true_prefilter = next(score for score, pair in prefilter_scores if pair == true_pair)
    prefilter_rank = 1 + sum(1 for score, _ in prefilter_scores if score > true_prefilter)
    best_wrong_prefilter = max(score for score, pair in prefilter_scores if pair != true_pair)

    exact_result = None
    if exact_top > 0:
        exact_candidates = [pair for _, pair in prefilter_scores[:exact_top]]
        if true_pair not in exact_candidates:
            exact_candidates.append(true_pair)
        exact_scores = []
        for pair in exact_candidates:
            if side == "right":
                score = score_visible_right(table, stage_idx, pair, diffs, sample_x, exact=True)
            else:
                assert state_word is not None
                score = score_visible_left(table, stage_idx, pair, state_word, diffs, sample_x, exact=True)
            exact_scores.append((score, pair))
        exact_scores.sort(key=lambda item: (-item[0], item[1]))
        true_exact = next(score for score, pair in exact_scores if pair == true_pair)
        exact_result = {
            "true_score": true_exact,
            "rank": 1 + sum(1 for score, _ in exact_scores if score > true_exact),
            "best_wrong": max(score for score, pair in exact_scores if pair != true_pair),
            "top": exact_scores[:10],
            "scored": len(exact_scores),
        }

    return {
        "stage": stage_idx,
        "side": side,
        "true_pair": true_pair,
        "lane_signature": signature,
        "class_size": total_size,
        "scanned": len(candidates),
        "exhaustive": exhaustive,
        "prefilter_true_score": true_prefilter,
        "prefilter_best_wrong": best_wrong_prefilter,
        "prefilter_rank": prefilter_rank,
        "prefilter_top": prefilter_scores[:10],
        "exact": exact_result,
    }


def state_guess_list(true_state_word: int, scan_mode: str) -> List[Tuple[int, int]]:
    if scan_mode == "low":
        return [(guess, guess) for guess in range(0x100)]
    if scan_mode == "nibble2":
        return [
            (guess, (true_state_word & 0x00FF) | ((guess & 0xF) << 8))
            for guess in range(0x10)
        ]
    if scan_mode == "upper":
        return [
            (guess, (true_state_word & 0x00FF) | ((guess & 0xFF) << 8))
            for guess in range(0x100)
        ]
    if scan_mode == "top":
        return [
            (guess, (true_state_word & 0x0FFF) | ((guess & 0xF) << 12))
            for guess in range(0x10)
        ]
    raise ValueError(f"unsupported state scan mode: {scan_mode}")


def state_true_label(true_state_word: int, scan_mode: str) -> int:
    if scan_mode == "low":
        return true_state_word & 0xFF
    if scan_mode == "nibble2":
        return (true_state_word >> 8) & 0xF
    if scan_mode == "upper":
        return (true_state_word >> 8) & 0xFF
    if scan_mode == "top":
        return (true_state_word >> 12) & 0xF
    raise ValueError(f"unsupported state scan mode: {scan_mode}")


def state_scan(
    table: Sequence[int],
    key_words: Sequence[int],
    state_words: Sequence[int],
    current_stage: int,
    side: str,
    true_state_word: int,
    diffs: Sequence[int],
    prefilter_diffs: Sequence[int],
    sample_x: Sequence[int],
    hi_values: Sequence[int],
    row_lo_values: Sequence[int],
    scan_mode: str,
) -> Dict[str, object]:
    current_pair = stage_key_pair(key_words, current_stage)
    next_stage = current_stage - 1 if side == "right" else current_stage + 1
    next_pair = stage_key_pair(key_words, next_stage)
    next_state_word = state_words[next_stage - 1]

    diff_pos = diff_positions(sample_x, sorted(set(diffs) | set(prefilter_diffs)))
    row_pos = [(hi << 8) | (lo & 0xFF) for hi in hi_values for lo in row_lo_values]
    union_pos = sorted(set(diff_pos) | set(row_pos))
    table_inv = invert_table(table) if side == "left" else None
    guesses = state_guess_list(true_state_word, scan_mode)

    results = []
    for label, guess_word in guesses:
        if side == "right":
            current_values = {
                pos: (dec_block(table[pos], current_pair, current_stage) - guess_word) & 0xFFFF
                for pos in union_pos
            }
            next_values = {
                pos: dec_block(current_values[pos], next_pair, next_stage)
                for pos in diff_pos
            }
            row_metric = sampled_row_branch_score_from_values(
                current_values,
                hi_values,
                row_lo_values,
            )
        else:
            assert table_inv is not None
            current_values = {
                pos: enc_block((table_inv[pos] + guess_word) & 0xFFFF, current_pair, current_stage)
                for pos in diff_pos
            }
            next_values = {
                pos: enc_block(
                    (current_values[pos] + next_state_word) & 0xFFFF,
                    next_pair,
                    next_stage,
                )
                for pos in diff_pos
            }
            row_metric = None
        results.append(
            {
                "label": label,
                "guess_word": guess_word,
                "row_metric": row_metric,
                "next_prefilter": prefilter_tuple_from_values(next_values, diffs, prefilter_diffs, sample_x),
            }
        )

    true_label = state_true_label(true_state_word, scan_mode)
    true_row = next(
        result["row_metric"]
        for result in results
        if result["label"] == true_label
    )
    true_next = next(
        result["next_prefilter"]
        for result in results
        if result["label"] == true_label
    )
    row_rank = None
    if true_row is not None:
        row_rank = 1 + sum(
            1
            for result in results
            if result["row_metric"] is not None and result["row_metric"] < true_row
        )
    next_rank = 1 + sum(1 for result in results if result["next_prefilter"] > true_next)
    return {
        "current_stage": current_stage,
        "next_stage": next_stage,
        "side": side,
        "true_state_word": true_state_word,
        "scan_mode": scan_mode,
        "results": results,
        "true_label": true_label,
        "true_row_metric": true_row,
        "true_next_prefilter": true_next,
        "row_rank": row_rank,
        "next_rank": next_rank,
    }


LADDER = [
    {
        "name": "Outer",
        "apply_left": [],
        "apply_right": [],
        "left_stage": 1,
        "right_stage": 8,
        "summary": "Original next-word permutation",
    },
    {
        "name": "B7..B2",
        "apply_left": [1],
        "apply_right": [8],
        "left_stage": 2,
        "right_stage": 7,
        "summary": "After peeling K1 and K8",
    },
    {
        "name": "B6..B2",
        "apply_left": [],
        "apply_right": [7],
        "left_stage": 2,
        "right_stage": 6,
        "summary": "After peeling K1, K7, and K8",
    },
    {
        "name": "B5..B3",
        "apply_left": [2],
        "apply_right": [6],
        "left_stage": 3,
        "right_stage": 5,
        "summary": "After peeling K1, K2, K6, K7, and K8",
    },
    {
        "name": "B4..B3",
        "apply_left": [],
        "apply_right": [5],
        "left_stage": 3,
        "right_stage": 4,
        "summary": "After peeling K1, K2, K5, K6, K7, and K8",
    },
]


def analyze_iv(
    iv_words: Sequence[int],
    key_words: Sequence[int],
    prefix_words: Sequence[int],
    diffs: Sequence[int],
    hi_values: Sequence[int],
    sample_x: Sequence[int],
    candidate_count: int,
    candidate_seed: int,
    *,
    exact: bool,
) -> Dict[str, object]:
    ctx = ctx_after_prefix(key_words, iv_words, prefix_words)
    state = ctx["state"]
    assert isinstance(state, list)

    table = next_word_table(ctx, key_words)
    current = table
    steps = []

    for step_cfg in LADDER:
        for stage_idx in step_cfg["apply_right"]:
            current = peel_right_exact(current, stage_idx, stage_key_pair(key_words, stage_idx), state[stage_idx - 1])
        for stage_idx in step_cfg["apply_left"]:
            current = peel_left_exact(current, stage_idx, stage_key_pair(key_words, stage_idx), state[stage_idx - 1])

        row_f = row_branch_score(current, hi_values)
        row_i = row_branch_score(invert_table(current), hi_values)
        left_info = rank_stage(
            current,
            key_words,
            step_cfg["left_stage"],
            "left",
            state[step_cfg["left_stage"] - 1],
            diffs,
            sample_x,
            candidate_count,
            candidate_seed,
            exact=exact,
        )
        right_info = rank_stage(
            current,
            key_words,
            step_cfg["right_stage"],
            "right",
            None,
            diffs,
            sample_x,
            candidate_count,
            candidate_seed,
            exact=exact,
        )
        steps.append(
            {
                "name": step_cfg["name"],
                "summary": step_cfg["summary"],
                "row_f": row_f,
                "row_i": row_i,
                "left": left_info,
                "right": right_info,
            }
        )

    return {
        "iv": list(iv_words),
        "prefix": list(prefix_words),
        "state": list(state),
        "steps": steps,
    }


def metric_label(step: Dict[str, object], side: str) -> str:
    info = step[side]
    assert isinstance(info, dict)
    return f"{step['name']} {side} K{info['stage']}"


def search_demo(
    trials: int,
    seed: int,
    key_words: Sequence[int],
    prefix_words: Sequence[int],
    diffs: Sequence[int],
    hi_values: Sequence[int],
    sample_x: Sequence[int],
    candidate_count: int,
    candidate_seed: int,
    *,
    exact: bool,
) -> Dict[str, object]:
    rng = random.Random(seed)
    best_by_metric: Dict[str, Dict[str, object]] = {}
    analyzed: List[Dict[str, object]] = []

    for trial in range(1, trials + 1):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        result = analyze_iv(
            iv_words,
            key_words,
            prefix_words,
            diffs,
            hi_values,
            sample_x,
            candidate_count,
            candidate_seed,
            exact=exact,
        )
        analyzed.append(result)

        step_summaries = []
        for step in result["steps"]:
            for side in ("left", "right"):
                info = step[side]
                assert isinstance(info, dict)
                label = metric_label(step, side)
                sort_key = (info["rank"], -info["gap"], -info["true_score"])
                existing = best_by_metric.get(label)
                if existing is None or sort_key < existing["sort_key"]:
                    best_by_metric[label] = {
                        "sort_key": sort_key,
                        "iv": list(iv_words),
                        "step_name": step["name"],
                        "side": side,
                        "info": info,
                        "row_f": step["row_f"],
                        "row_i": step["row_i"],
                    }
                step_summaries.append(
                    f"{side[0].upper()}K{info['stage']}:r{info['rank']}/g{info['gap']}/s{info['true_score']}"
                )

        print(
            f"trial {trial}/{trials} iv={words_to_hex(iv_words)} | "
            + " | ".join(step_summaries)
        )

    return {"best_by_metric": best_by_metric, "analyzed": analyzed}


def print_analysis(result: Dict[str, object]) -> None:
    print(f"IV     = {words_to_hex(result['iv'])}")
    print(f"state  = {[f'{word:04X}' for word in result['state']]}")
    if result["prefix"]:
        print(f"prefix = {[f'{word:04X}' for word in result['prefix']]}")
    print()

    for step in result["steps"]:
        print(f"{step['name']}: {step['summary']}")
        print(f"  row_f = {step['row_f']:.2f}")
        print(f"  row_i = {step['row_i']:.2f}")
        for side in ("left", "right"):
            info = step[side]
            assert isinstance(info, dict)
            print(
                f"  {side}: K{info['stage']}={info['true_pair']} "
                f"rank={info['rank']} gap={info['gap']} score={info['true_score']}"
            )
            print(f"    top = {info['top']}")
        print()


def choose_unique_best_ivs(best_by_metric: Dict[str, Dict[str, object]], limit: int) -> List[List[int]]:
    seen = set()
    chosen = []
    for _, entry in sorted(best_by_metric.items(), key=lambda item: item[1]["sort_key"]):
        iv_tuple = tuple(entry["iv"])
        if iv_tuple not in seen:
            seen.add(iv_tuple)
            chosen.append(list(iv_tuple))
            if len(chosen) >= limit:
                break
    return chosen


def print_lane_scan(label: str, result: Dict[str, object]) -> None:
    print(
        f"{label}: stage=K{result['stage']} side={result['side']} "
        f"true={result['true_pair']} lane_sig={result['lane_signature']}"
    )
    print(
        f"  lane class size={result['class_size']} scanned={result['scanned']} "
        f"exhaustive={result['exhaustive']}"
    )
    print(
        f"  prefilter rank={result['prefilter_rank']} "
        f"true={result['prefilter_true_score']} "
        f"best_wrong={result['prefilter_best_wrong']}"
    )
    print(f"  prefilter top={result['prefilter_top']}")
    exact = result["exact"]
    if exact is not None:
        assert isinstance(exact, dict)
        print(
            f"  exact(top {exact['scored']}) rank={exact['rank']} "
            f"gap={exact['true_score'] - exact['best_wrong']} "
            f"score={exact['true_score']}"
        )
        print(f"  exact top={exact['top']}")


def print_state_scan(label: str, result: Dict[str, object]) -> None:
    print(
        f"{label}: recover s{result['current_stage']} on {result['side']} side "
        f"via K{result['next_stage']} visibility"
    )
    print(
        f"  true state={result['true_state_word']:04X} "
        f"scan={result['scan_mode']} true_label={result['true_label']:X}"
    )
    print(
        f"  next-stage prefilter rank={result['next_rank']} "
        f"true={result['true_next_prefilter']}"
    )
    top_next = sorted(result["results"], key=lambda item: (item["next_prefilter"], item["label"]), reverse=True)[:10]
    print(
        "  best next-stage="
        + str([(item["label"], item["guess_word"], item["next_prefilter"]) for item in top_next])
    )
    if result["row_rank"] is not None:
        print(
            f"  row-branch rank={result['row_rank']} "
            f"true={result['true_row_metric']:.2f}"
        )
        top_row = sorted(result["results"], key=lambda item: (item["row_metric"], item["label"]))[:10]
        print(
            "  best row="
            + str([(item["label"], item["guess_word"], item["row_metric"]) for item in top_row])
        )


def state_search_summary(result: Dict[str, object]) -> Dict[str, object]:
    top_next = sorted(result["results"], key=lambda item: (item["next_prefilter"], item["label"]), reverse=True)[0]
    best_row = None
    if result["row_rank"] is not None:
        best_row = min(item["row_metric"] for item in result["results"] if item["row_metric"] is not None)
    return {
        "true_label": result["true_label"],
        "next_rank": result["next_rank"],
        "row_rank": result["row_rank"],
        "true_next_prefilter": result["true_next_prefilter"],
        "top_next_label": top_next["label"],
        "top_next_guess": top_next["guess_word"],
        "top_next_prefilter": top_next["next_prefilter"],
        "true_row_metric": result["true_row_metric"],
        "best_row_metric": best_row,
    }


def search_state_contexts(
    trials: int,
    seed: int,
    key_words: Sequence[int],
    prefix_words: Sequence[int],
    left_peels: Sequence[int],
    right_peels: Sequence[int],
    side: str,
    current_stage: int,
    diffs: Sequence[int],
    prefilter_diffs: Sequence[int],
    sample_x: Sequence[int],
    hi_values: Sequence[int],
    row_lo_values: Sequence[int],
    scan_mode: str,
) -> List[Dict[str, object]]:
    rng = random.Random(seed)
    results = []
    for trial in range(1, trials + 1):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        table, ctx = reduce_table_for_context(key_words, iv_words, prefix_words, left_peels, right_peels)
        state = ctx["state"]
        assert isinstance(state, list)
        scan = state_scan(
            table,
            key_words,
            state,
            current_stage,
            side,
            state[current_stage - 1],
            diffs,
            prefilter_diffs,
            sample_x,
            hi_values,
            row_lo_values,
            scan_mode,
        )
        summary = state_search_summary(scan)
        results.append(
            {
                "iv": list(iv_words),
                "scan": scan,
                "summary": summary,
            }
        )
        print(
            f"trial {trial}/{trials} iv={words_to_hex(iv_words)} "
            f"true={summary['true_label']:X} "
            f"next_rank={summary['next_rank']} "
            f"top_next={summary['top_next_label']:X} "
            f"pref={summary['true_next_prefilter']} "
            f"row_rank={summary['row_rank']}"
        )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Standalone SEPAR recursive stage-peel demo: IV search, true-key scoring, and exact peel ladder."
    )
    parser.add_argument(
        "--mode",
        choices=["demo", "analyze", "lane-bound", "state-scan", "state-search"],
        default="demo",
    )
    parser.add_argument("--key", help="optional 64-hex full key; defaults to the implementation's built-in key")
    parser.add_argument("--iv", help="IV for analyze or lane-bound mode")
    parser.add_argument("--prefix", default="", help="comma-separated plaintext prefix words in hex")
    parser.add_argument("--trials", type=int, default=6, help="random IV trials in demo mode")
    parser.add_argument("--seed", type=int, default=0x53455041, help="PRNG seed")
    parser.add_argument("--candidate-count", type=int, default=12, help="number of key candidates per scored stage")
    parser.add_argument("--candidate-seed", type=int, default=1, help="PRNG seed for wrong-key candidates")
    parser.add_argument("--hi-values", default=",".join(f"{v:02x}" for v in DEFAULT_HI_VALUES))
    parser.add_argument("--diffs", default=",".join(f"{d:04x}" for d in DEFAULT_DIFFS))
    parser.add_argument(
        "--prefilter-diffs",
        default=",".join(f"{d:04x}" for d in DEFAULT_PREFILTER_DIFFS),
        help="comma-separated additive diffs for the cheap triangularity prefilter",
    )
    parser.add_argument("--sample-step", type=int, default=257, help="sample stride for sampled scoring")
    parser.add_argument("--sample-count", type=int, default=256, help="number of sampled x values")
    parser.add_argument("--exact", action="store_true", help="use exact 65536-point scoring instead of sampled scoring")
    parser.add_argument("--left-peels", default="", help="comma-separated exact left peels for lane-bound mode")
    parser.add_argument("--right-peels", default="", help="comma-separated exact right peels for lane-bound mode")
    parser.add_argument("--target-left", type=int, help="visible left stage for lane-bound mode")
    parser.add_argument("--target-right", type=int, help="visible right stage for lane-bound mode")
    parser.add_argument("--side", choices=["both", "left", "right"], default="both", help="which side to lane-scan")
    parser.add_argument(
        "--state-scan-mode",
        choices=["low", "nibble2", "upper", "top"],
        default="low",
        help="which part of the current visible state word to scan in state-scan mode",
    )
    parser.add_argument("--row-lo-step", type=int, default=17, help="sampled low-byte stride for state row-branch scans")
    parser.add_argument(
        "--class-limit",
        type=int,
        default=2048,
        help="limit candidates scanned inside the true lane class; 0 means exhaustive",
    )
    parser.add_argument("--class-seed", type=int, default=1, help="PRNG seed for sampled lane-class scans")
    parser.add_argument("--exact-top", type=int, default=16, help="after sampled lane scan, exact-score this many top survivors")
    parser.add_argument(
        "--analyze-best",
        type=int,
        default=3,
        help="in demo mode, run detailed analysis on up to this many unique best IVs",
    )
    args = parser.parse_args()

    key_words = parse_full_key_hex(args.key) if args.key else list(DEFAULT_KEY)
    prefix_words = parse_word_list(args.prefix)
    hi_values = [value & 0xFF for value in parse_word_list(args.hi_values)]
    diffs = parse_word_list(args.diffs)
    prefilter_diffs = parse_word_list(args.prefilter_diffs)
    sample_x = list(range(0, 0x10000, args.sample_step))[: args.sample_count]
    row_lo_values = list(range(0, 0x100, max(1, args.row_lo_step)))

    if args.mode == "lane-bound":
        if args.iv is None:
            raise SystemExit("--iv is required in lane-bound mode")
        left_peels = parse_stage_list(args.left_peels)
        right_peels = parse_stage_list(args.right_peels)
        target_left = args.target_left if args.target_left is not None else derive_visible_stage(left_peels, "left")
        target_right = args.target_right if args.target_right is not None else derive_visible_stage(right_peels, "right")

        table, ctx = reduce_table_for_context(
            key_words,
            parse_full_iv_hex(args.iv),
            prefix_words,
            left_peels,
            right_peels,
        )
        state = ctx["state"]
        assert isinstance(state, list)

        print(f"IV          = {args.iv.upper()}")
        print(f"prefix      = {[f'{word:04X}' for word in prefix_words]}")
        print(f"left peels  = {left_peels}")
        print(f"right peels = {right_peels}")
        print(f"row_f       = {row_branch_score(table, hi_values):.2f}")
        print(f"row_i       = {row_branch_score(invert_table(table), hi_values):.2f}")
        print(f"state       = {[f'{word:04X}' for word in state]}")
        print()

        class_limit = None if args.class_limit <= 0 else args.class_limit

        if args.side in ("both", "left"):
            left_result = lane_class_scan(
                table,
                key_words,
                target_left,
                "left",
                state[target_left - 1],
                diffs,
                prefilter_diffs,
                sample_x,
                class_limit,
                args.class_seed,
                args.exact_top,
            )
            print_lane_scan("Left", left_result)
            print()

        if args.side in ("both", "right"):
            right_result = lane_class_scan(
                table,
                key_words,
                target_right,
                "right",
                None,
                diffs,
                prefilter_diffs,
                sample_x,
                class_limit,
                args.class_seed,
                args.exact_top,
            )
            print_lane_scan("Right", right_result)
        return

    if args.mode == "state-scan":
        if args.iv is None:
            raise SystemExit("--iv is required in state-scan mode")
        left_peels = parse_stage_list(args.left_peels)
        right_peels = parse_stage_list(args.right_peels)
        target_left = args.target_left if args.target_left is not None else derive_visible_stage(left_peels, "left")
        target_right = args.target_right if args.target_right is not None else derive_visible_stage(right_peels, "right")

        table, ctx = reduce_table_for_context(
            key_words,
            parse_full_iv_hex(args.iv),
            prefix_words,
            left_peels,
            right_peels,
        )
        state = ctx["state"]
        assert isinstance(state, list)

        print(f"IV          = {args.iv.upper()}")
        print(f"prefix      = {[f'{word:04X}' for word in prefix_words]}")
        print(f"left peels  = {left_peels}")
        print(f"right peels = {right_peels}")
        print(f"row_f       = {row_branch_score(table, hi_values):.2f}")
        print(f"row_i       = {row_branch_score(invert_table(table), hi_values):.2f}")
        print(f"state       = {[f'{word:04X}' for word in state]}")
        print()

        if args.side in ("both", "right"):
            current_stage = target_right
            if current_stage <= 1:
                raise SystemExit("right state scan requires a visible stage above K1")
            right_result = state_scan(
                table,
                key_words,
                state,
                current_stage,
                "right",
                state[current_stage - 1],
                diffs,
                prefilter_diffs,
                sample_x,
                hi_values,
                row_lo_values,
                args.state_scan_mode,
            )
            print_state_scan("Right", right_result)
            if args.side == "both":
                print()

        if args.side in ("both", "left"):
            current_stage = target_left
            if current_stage >= 8:
                raise SystemExit("left state scan requires a visible stage below K8")
            left_result = state_scan(
                table,
                key_words,
                state,
                current_stage,
                "left",
                state[current_stage - 1],
                diffs,
                prefilter_diffs,
                sample_x,
                hi_values,
                row_lo_values,
                args.state_scan_mode,
            )
            print_state_scan("Left", left_result)
        return

    if args.mode == "state-search":
        if args.iv is not None:
            raise SystemExit("--iv is not used in state-search mode")
        if args.side == "both":
            raise SystemExit("--side must be left or right in state-search mode")
        left_peels = parse_stage_list(args.left_peels)
        right_peels = parse_stage_list(args.right_peels)
        current_stage = (
            args.target_left if args.side == "left" and args.target_left is not None
            else args.target_right if args.side == "right" and args.target_right is not None
            else derive_visible_stage(left_peels, "left") if args.side == "left"
            else derive_visible_stage(right_peels, "right")
        )

        results = search_state_contexts(
            args.trials,
            args.seed,
            key_words,
            prefix_words,
            left_peels,
            right_peels,
            args.side,
            current_stage,
            diffs,
            prefilter_diffs,
            sample_x,
            hi_values,
            row_lo_values,
            args.state_scan_mode,
        )

        def sort_key(item: Dict[str, object]) -> Tuple[object, ...]:
            summary = item["summary"]
            assert isinstance(summary, dict)
            row_rank = summary["row_rank"] if summary["row_rank"] is not None else 0xFFFF
            pref = summary["true_next_prefilter"]
            assert isinstance(pref, tuple)
            return (
                summary["next_rank"],
                row_rank,
                -pref[0],
                -pref[1],
                -pref[2],
            )

        print()
        print("Best State-Recovery IVs")
        for item in sorted(results, key=sort_key)[:10]:
            summary = item["summary"]
            assert isinstance(summary, dict)
            print(
                f"  iv={words_to_hex(item['iv'])} "
                f"true={summary['true_label']:X} "
                f"next_rank={summary['next_rank']} "
                f"top_next={summary['top_next_label']:X} "
                f"pref={summary['true_next_prefilter']} "
                f"row_rank={summary['row_rank']}"
            )

        chosen = []
        seen = set()
        for item in sorted(results, key=sort_key):
            iv_tuple = tuple(item["iv"])
            if iv_tuple not in seen:
                seen.add(iv_tuple)
                chosen.append(item)
                if len(chosen) >= args.analyze_best:
                    break

        if chosen:
            print()
            print("Detailed State Scans")
            for item in chosen:
                print(f"IV          = {words_to_hex(item['iv'])}")
                print_state_scan(args.side.capitalize(), item["scan"])
                print()
        return

    if args.mode == "analyze":
        if args.iv is None:
            raise SystemExit("--iv is required in analyze mode")
        result = analyze_iv(
            parse_full_iv_hex(args.iv),
            key_words,
            prefix_words,
            diffs,
            hi_values,
            sample_x,
            args.candidate_count,
            args.candidate_seed,
            exact=args.exact,
        )
        print_analysis(result)
        return

    search = search_demo(
        args.trials,
        args.seed,
        key_words,
        prefix_words,
        diffs,
        hi_values,
        sample_x,
        args.candidate_count,
        args.candidate_seed,
        exact=False if not args.exact else True,
    )

    print()
    print("Best IV per metric")
    for label, entry in sorted(search["best_by_metric"].items(), key=lambda item: item[1]["sort_key"]):
        info = entry["info"]
        print(
            f"  {label}: iv={words_to_hex(entry['iv'])} "
            f"rank={info['rank']} gap={info['gap']} score={info['true_score']} "
            f"row_f={entry['row_f']:.2f} row_i={entry['row_i']:.2f}"
        )

    chosen = choose_unique_best_ivs(search["best_by_metric"], args.analyze_best)
    if not chosen:
        return

    print()
    print("Detailed Analysis of Best IVs")
    for iv_words in chosen:
        result = analyze_iv(
            iv_words,
            key_words,
            prefix_words,
            diffs,
            hi_values,
            sample_x,
            args.candidate_count,
            args.candidate_seed,
            exact=True,
        )
        print_analysis(result)


if __name__ == "__main__":
    main()
