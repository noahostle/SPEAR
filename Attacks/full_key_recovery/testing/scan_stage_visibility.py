#!/usr/bin/env python3

import argparse
import random
from typing import Dict, List, Optional, Sequence, Tuple

from hb1_style_stage_peel import (
    DEFAULT_DIFFS,
    enc_block,
    dec_block,
    parse_full_iv_hex,
    parse_full_key_hex,
    parse_word_list,
    words_to_hex,
)


DEFAULT_KEY = [
    0xE8B9, 0xB733, 0xDA5D, 0x96D7, 0x02DD, 0x3972, 0xE953, 0x07FD,
    0x50C5, 0x12DB, 0xF44A, 0x233E, 0x8D1E, 0x9DF5, 0xFC7D, 0x6371,
]
DEFAULT_HI_VALUES = [0x00, 0x20, 0x40, 0x80, 0xA0, 0xFF]
DEFAULT_SAMPLE_X = list(range(0, 0x10000, 257))[:256]


def stage_key_pair(key_words: Sequence[int], stage_idx: int) -> Tuple[int, int]:
    base = 2 * (stage_idx - 1)
    return key_words[base], key_words[base + 1]


def initial_ctx(key_words: Sequence[int], iv_words: Sequence[int]) -> Dict[str, List[int] | int]:
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


def advance_ctx_encrypt_word(ctx: Dict[str, List[int] | int], key_words: Sequence[int], pt: int) -> int:
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
    ctx = initial_ctx(key_words, iv_words)
    for pt in prefix_words:
        advance_ctx_encrypt_word(ctx, key_words, pt)
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


def peel_right_exact(
    table: Sequence[int],
    key_words: Sequence[int],
    ctx_state_words: Sequence[int],
    stage_idx: int,
) -> List[int]:
    pair = stage_key_pair(key_words, stage_idx)
    state_word = ctx_state_words[stage_idx - 1]
    return [((dec_block(value, pair, stage_idx) - state_word) & 0xFFFF) for value in table]


def peel_left_exact(
    table: Sequence[int],
    key_words: Sequence[int],
    ctx_state_words: Sequence[int],
    stage_idx: int,
) -> List[int]:
    pair = stage_key_pair(key_words, stage_idx)
    state_word = ctx_state_words[stage_idx - 1]
    out = [0] * 0x10000
    for x, value in enumerate(table):
        u = enc_block((x + state_word) & 0xFFFF, pair, stage_idx)
        out[u] = value
    return out


def row_branch_score(table: Sequence[int], hi_values: Sequence[int]) -> float:
    total = 0
    for hi in hi_values:
        values = set()
        base = (hi & 0xFF) << 8
        for lo in range(256):
            values.add((table[base | lo] >> 8) & 0xFF)
        total += len(values)
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


def candidate_pool(true_pair: Tuple[int, int], count: int, seed: int) -> List[Tuple[int, int]]:
    candidates = [true_pair, (0x0000, 0x0000), (0x1111, 0x2222), (0xBEEF, 0x1234)]
    rng = random.Random(seed)
    seen = set(candidates)
    while len(candidates) < count:
        pair = (rng.randrange(0x10000), rng.randrange(0x10000))
        if pair not in seen:
            seen.add(pair)
            candidates.append(pair)
    return candidates


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
    if exact:
        return exact_diff_score(peeled, diffs)
    return sampled_diff_score(peeled, diffs, sample_x)


def score_visible_left(
    table: Sequence[int],
    stage_idx: int,
    state_word: int,
    pair: Tuple[int, int],
    diffs: Sequence[int],
    sample_x: Sequence[int],
    *,
    exact: bool,
) -> int:
    inverse = invert_table(table)
    peeled = [enc_block((value + state_word) & 0xFFFF, pair, stage_idx) for value in inverse]
    if exact:
        return exact_diff_score(peeled, diffs)
    return sampled_diff_score(peeled, diffs, sample_x)


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
            score = score_visible_left(table, stage_idx, state_word, pair, diffs, sample_x, exact=exact)
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


def parse_stage_list(text: str) -> List[int]:
    return sorted({int(part.strip(), 10) for part in text.split(",") if part.strip()})


def derive_visible_stage(peels: Sequence[int], side: str) -> int:
    if not peels:
        return 1 if side == "left" else 8
    if side == "left":
        return max(peels) + 1
    return min(peels) - 1


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
        table = peel_right_exact(table, key_words, state, stage_idx)
    for stage_idx in sorted(left_peels):
        table = peel_left_exact(table, key_words, state, stage_idx)

    return table, ctx


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan which reduced SEPAR stages become visible after exact outer peels."
    )
    parser.add_argument("--mode", choices=["single", "search"], default="single")
    parser.add_argument("--key", help="optional 64-hex full key; default is the implementation's built-in key")
    parser.add_argument("--iv", help="IV for single mode")
    parser.add_argument("--prefix", default="", help="comma-separated plaintext prefix words in hex")
    parser.add_argument("--left-peels", default="", help="comma-separated exact left stage peels")
    parser.add_argument("--right-peels", default="", help="comma-separated exact right stage peels")
    parser.add_argument("--target-left", type=int, help="visible left stage to score; default derives from peels")
    parser.add_argument("--target-right", type=int, help="visible right stage to score; default derives from peels")
    parser.add_argument("--hi-values", default=",".join(f"{v:02x}" for v in DEFAULT_HI_VALUES))
    parser.add_argument("--diffs", default=",".join(f"{d:04x}" for d in DEFAULT_DIFFS))
    parser.add_argument("--candidate-count", type=int, default=20)
    parser.add_argument("--candidate-seed", type=int, default=1)
    parser.add_argument("--sample-step", type=int, default=257, help="sample stride for search mode")
    parser.add_argument("--sample-count", type=int, default=256, help="sample count for search mode")
    parser.add_argument("--trials", type=int, default=8, help="random IV trials in search mode")
    parser.add_argument("--seed", type=int, default=0x53455041, help="PRNG seed for random IV search")
    parser.add_argument("--exact", action="store_true", help="use exact full 65536-point differential scoring")
    args = parser.parse_args()

    key_words = parse_full_key_hex(args.key) if args.key else list(DEFAULT_KEY)
    prefix_words = parse_word_list(args.prefix)
    left_peels = parse_stage_list(args.left_peels)
    right_peels = parse_stage_list(args.right_peels)
    target_left = args.target_left if args.target_left is not None else derive_visible_stage(left_peels, "left")
    target_right = args.target_right if args.target_right is not None else derive_visible_stage(right_peels, "right")
    hi_values = [value & 0xFF for value in parse_word_list(args.hi_values)]
    diffs = parse_word_list(args.diffs)
    sample_x = list(range(0, 0x10000, args.sample_step))[: args.sample_count]

    def analyze_iv(iv_words: Sequence[int]) -> Dict[str, object]:
        table, ctx = reduce_table_for_context(key_words, iv_words, prefix_words, left_peels, right_peels)
        state = ctx["state"]
        assert isinstance(state, list)

        left_result = rank_stage(
            table,
            key_words,
            target_left,
            "left",
            state[target_left - 1],
            diffs,
            sample_x,
            args.candidate_count,
            args.candidate_seed,
            exact=args.exact,
        )
        right_result = rank_stage(
            table,
            key_words,
            target_right,
            "right",
            None,
            diffs,
            sample_x,
            args.candidate_count,
            args.candidate_seed,
            exact=args.exact,
        )
        return {
            "iv": list(iv_words),
            "row_f": row_branch_score(table, hi_values),
            "row_i": row_branch_score(invert_table(table), hi_values),
            "left": left_result,
            "right": right_result,
            "state": state,
        }

    if args.mode == "single":
        if args.iv is None:
            raise SystemExit("--iv is required in single mode")
        result = analyze_iv(parse_full_iv_hex(args.iv))
        print(f"IV          = {words_to_hex(result['iv'])}")
        print(f"left peels  = {left_peels}")
        print(f"right peels = {right_peels}")
        print(f"row_f       = {result['row_f']:.2f}")
        print(f"row_i       = {result['row_i']:.2f}")
        print(f"state       = {[f'{word:04X}' for word in result['state']]}")
        print()
        for label in ("left", "right"):
            info = result[label]
            print(
                f"{label}: stage={info['stage']} true={info['true_pair']} "
                f"rank={info['rank']} gap={info['gap']} score={info['true_score']}"
            )
            print(f"  top={info['top']}")
        return

    rng = random.Random(args.seed)
    results = []
    for trial in range(1, args.trials + 1):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        result = analyze_iv(iv_words)
        results.append(result)
        print(
            f"trial {trial}/{args.trials} iv={words_to_hex(iv_words)} "
            f"row_f={result['row_f']:.2f} row_i={result['row_i']:.2f} "
            f"L(rank={result['left']['rank']},gap={result['left']['gap']}) "
            f"R(rank={result['right']['rank']},gap={result['right']['gap']})"
        )

    print()
    print("Best left-stage contexts")
    for result in sorted(results, key=lambda item: (item["left"]["rank"], -item["left"]["gap"], item["row_i"]))[:5]:
        print(
            f"  iv={words_to_hex(result['iv'])} "
            f"L(rank={result['left']['rank']},gap={result['left']['gap']},score={result['left']['true_score']}) "
            f"R(rank={result['right']['rank']},gap={result['right']['gap']},score={result['right']['true_score']}) "
            f"row_f={result['row_f']:.2f} row_i={result['row_i']:.2f}"
        )

    print()
    print("Best right-stage contexts")
    for result in sorted(results, key=lambda item: (item["right"]["rank"], -item["right"]["gap"], item["row_f"]))[:5]:
        print(
            f"  iv={words_to_hex(result['iv'])} "
            f"L(rank={result['left']['rank']},gap={result['left']['gap']},score={result['left']['true_score']}) "
            f"R(rank={result['right']['rank']},gap={result['right']['gap']},score={result['right']['true_score']}) "
            f"row_f={result['row_f']:.2f} row_i={result['row_i']:.2f}"
        )


if __name__ == "__main__":
    main()
