#!/usr/bin/env python3

from __future__ import annotations

import argparse
import random
import struct
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

from separ_analysis import (
    DEFAULT_IV,
    DEFAULT_KEY,
    DllOracle,
    SeparCtx,
    dec_block,
    encrypt_word,
    initial_state,
)


MASK16 = 0xFFFF
CODEBOOK_WORDS = 1 << 16


def _u16(x: int) -> int:
    return x & MASK16


def keypair_from_index(index: int) -> Tuple[int, int]:
    return ((index >> 16) & MASK16, index & MASK16)


def index_from_keypair(keypair: Sequence[int]) -> int:
    return ((keypair[0] & MASK16) << 16) | (keypair[1] & MASK16)


def save_codebook(path: Path, codebook: Sequence[int]) -> None:
    with path.open("wb") as f:
        for word in codebook:
            f.write(struct.pack("<H", word & MASK16))


def load_codebook(path: Path) -> List[int]:
    data = path.read_bytes()
    if len(data) != CODEBOOK_WORDS * 2:
        raise ValueError(f"expected {CODEBOOK_WORDS * 2} bytes, got {len(data)}")
    return list(struct.unpack("<" + ("H" * CODEBOOK_WORDS), data))


def build_first_block_codebook_local(
    key: Sequence[int] = DEFAULT_KEY,
    iv: Sequence[int] = DEFAULT_IV,
) -> List[int]:
    base = initial_state(key, iv)
    out = [0] * CODEBOOK_WORDS
    for pt in range(CODEBOOK_WORDS):
        ctx = SeparCtx(**base.__dict__)
        out[pt] = encrypt_word(pt, ctx, key)
    return out


def build_first_block_codebook_dll(
    dll_path: str | Path = Path("SEPAR") / "SEPAR.dll",
    key: Sequence[int] | None = None,
    iv: Sequence[int] | None = None,
) -> List[int]:
    if key is None:
        key = DEFAULT_KEY
    if iv is None:
        iv = DEFAULT_IV
    oracle = DllOracle(dll_path)
    out = [0] * CODEBOOK_WORDS
    for pt in range(CODEBOOK_WORDS):
        out[pt] = oracle.encrypt_words([pt], key, iv)[0]
    return out


def sample_high_values(sample_highs: int) -> List[int]:
    if sample_highs <= 0:
        raise ValueError("sample_highs must be positive")
    step = 256 // sample_highs
    if step <= 0 or 256 % sample_highs != 0:
        raise ValueError("sample_highs must divide 256")
    return list(range(0, 256, step))


def sample_low_values(low_step: int) -> List[int]:
    if low_step <= 0 or 256 % low_step != 0:
        raise ValueError("low_step must be a positive divisor of 256")
    return list(range(0, 256, low_step))


def sampled_output_stage_score(
    codebook: Sequence[int],
    stage_num: int,
    keypair: Sequence[int],
    state_low_guess: int,
    high_values: Sequence[int],
    low_values: Sequence[int],
) -> int:
    total = 0
    for high in high_values:
        seen = set()
        for low in low_values:
            value = codebook[(high << 8) | low]
            residual = _u16(dec_block(value, keypair, stage_num) - state_low_guess)
            seen.add(residual >> 8)
        total += len(seen)
    return total


def best_sampled_output_stage_score(
    codebook: Sequence[int],
    stage_num: int,
    keypair: Sequence[int],
    high_values: Sequence[int],
    low_values: Sequence[int],
) -> Tuple[int, int]:
    best_score = None
    best_low = None
    for low_guess in range(256):
        score = sampled_output_stage_score(codebook, stage_num, keypair, low_guess, high_values, low_values)
        if best_score is None or score < best_score:
            best_score = score
            best_low = low_guess
    return best_score if best_score is not None else 0, best_low if best_low is not None else 0


def exact_output_stage_score(
    codebook: Sequence[int],
    stage_num: int,
    keypair: Sequence[int],
    state_low_guess: int,
) -> float:
    total = 0
    for high in range(256):
        seen = set()
        for low in range(256):
            value = codebook[(high << 8) | low]
            residual = _u16(dec_block(value, keypair, stage_num) - state_low_guess)
            seen.add(residual >> 8)
        total += len(seen)
    return total / 256.0


def best_exact_output_stage_score(
    codebook: Sequence[int],
    stage_num: int,
    keypair: Sequence[int],
) -> Tuple[float, int]:
    best_score = None
    best_low = None
    for low_guess in range(256):
        score = exact_output_stage_score(codebook, stage_num, keypair, low_guess)
        if best_score is None or score < best_score:
            best_score = score
            best_low = low_guess
    return best_score if best_score is not None else 0.0, best_low if best_low is not None else 0


def recover_input_state_low_byte(
    codebook: Sequence[int],
    stage_num: int,
    arbitrary_keypair: Sequence[int] = (0, 0),
    sample_highs: int = 16,
) -> Tuple[float, int]:
    highs = sample_high_values(sample_highs)
    best_score = None
    best_low = None
    for low_guess in range(256):
        total = 0
        for high in highs:
            seen = set()
            for low in range(256):
                vin = (high << 8) | low
                pt = _u16(dec_block(vin, arbitrary_keypair, stage_num) - low_guess)
                seen.add(codebook[pt] >> 8)
            total += len(seen)
        score = total / len(highs)
        if best_score is None or score < best_score:
            best_score = score
            best_low = low_guess
    return best_score if best_score is not None else 0.0, best_low if best_low is not None else 0


def peel_output_stage(codebook: Sequence[int], stage_num: int, keypair: Sequence[int], state_word: int) -> List[int]:
    out = [0] * CODEBOOK_WORDS
    for idx, value in enumerate(codebook):
        out[idx] = _u16(dec_block(value, keypair, stage_num) - state_word)
    return out


def true_first_block_codebook() -> Tuple[List[int], List[Tuple[int, int]], List[int]]:
    base = initial_state(DEFAULT_KEY, DEFAULT_IV)
    codebook = [0] * CODEBOOK_WORDS
    for pt in range(CODEBOOK_WORDS):
        ctx = SeparCtx(**base.__dict__)
        codebook[pt] = encrypt_word(pt, ctx, DEFAULT_KEY)
    keypairs = [tuple(DEFAULT_KEY[i : i + 2]) for i in range(0, 16, 2)]
    states = [
        base.state_1,
        base.state_2,
        base.state_3,
        base.state_4,
        base.state_5,
        base.state_6,
        base.state_7,
        base.state_8,
    ]
    return codebook, keypairs, states


def peel_true_outer_stages(target_stage: int) -> Tuple[List[int], Tuple[int, int], int]:
    codebook, keypairs, states = true_first_block_codebook()
    # target_stage uses SEPAR numbering 1..8. Peel 8,7,...,target_stage+1.
    for stage in range(8, target_stage, -1):
        codebook = peel_output_stage(codebook, stage, keypairs[stage - 1], states[stage - 1])
    return codebook, keypairs[target_stage - 1], states[target_stage - 1]


def demo_rank_stage(target_stage: int, random_candidates: int, sample_highs: int, low_step: int, seed: int) -> None:
    codebook, true_keypair, true_state = peel_true_outer_stages(target_stage)
    rng = random.Random(seed)
    highs = sample_high_values(sample_highs)
    lows = sample_low_values(low_step)

    results = []
    score, best_low = best_sampled_output_stage_score(codebook, target_stage, true_keypair, highs, lows)
    results.append((score, "true", true_keypair, best_low))

    seen = {true_keypair}
    while len(seen) < random_candidates + 1:
        candidate = (rng.randrange(65536), rng.randrange(65536))
        if candidate in seen:
            continue
        seen.add(candidate)
        score, best_low = best_sampled_output_stage_score(codebook, target_stage, candidate, highs, lows)
        results.append((score, "rand", candidate, best_low))

    results.sort()
    print(f"Stage {target_stage} sampled-score ranking")
    print(f"True keypair: {true_keypair[0]:04X}{true_keypair[1]:04X}")
    print(f"True state low byte: {true_state & 0xFF:02X}")
    for row in results[:10]:
        score, label, keypair, best_low = row
        print(f"  score={score:4d}  low={best_low:02X}  {label:4s}  {keypair[0]:04X}{keypair[1]:04X}")
    rank = next(i for i, row in enumerate(results, 1) if row[1] == "true")
    print(f"True rank: {rank}/{len(results)}")


def score_key_range(
    codebook: Sequence[int],
    stage_num: int,
    start_index: int,
    count: int,
    sample_highs: int,
    low_step: int,
    exact: bool,
) -> List[Tuple[float, int, Tuple[int, int], int]]:
    highs = sample_high_values(sample_highs)
    lows = sample_low_values(low_step)
    results = []
    end_index = min(start_index + count, 1 << 32)
    for index in range(start_index, end_index):
        keypair = keypair_from_index(index)
        if exact:
            score, best_low = best_exact_output_stage_score(codebook, stage_num, keypair)
        else:
            score, best_low = best_sampled_output_stage_score(codebook, stage_num, keypair, highs, lows)
        results.append((score, index, keypair, best_low))
    results.sort()
    return results


def precompute_dec_table(stage_num: int, keypair: Sequence[int]) -> List[int]:
    return [dec_block(value, keypair, stage_num) for value in range(CODEBOOK_WORDS)]


def decode_output_stage(codebook: Sequence[int], stage_num: int, keypair: Sequence[int]) -> List[int]:
    out = [0] * CODEBOOK_WORDS
    for idx, value in enumerate(codebook):
        out[idx] = dec_block(value, keypair, stage_num)
    return out


def state_high_candidate_score(
    decoded_codebook: Sequence[int],
    peeled_state_low: int,
    state_high_guess: int,
    next_stage_table: Sequence[int],
    next_state_low_guess: int,
    high_values: Sequence[int],
    low_values: Sequence[int],
) -> int:
    state_guess = ((state_high_guess & 0xFF) << 8) | (peeled_state_low & 0xFF)
    total = 0
    for high in high_values:
        seen = set()
        for low in low_values:
            idx = (high << 8) | low
            peeled = _u16(decoded_codebook[idx] - state_guess)
            residual = _u16(next_stage_table[peeled] - next_state_low_guess)
            seen.add(residual >> 8)
        total += len(seen)
    return total


def rank_state_high_candidates(
    decoded_codebook: Sequence[int],
    peeled_state_low: int,
    next_stage_table: Sequence[int],
    high_values: Sequence[int],
    low_values: Sequence[int],
) -> List[Tuple[int, int, int]]:
    results = []
    for state_high_guess in range(256):
        best_score = None
        best_next_low = None
        for next_state_low_guess in range(256):
            score = state_high_candidate_score(
                decoded_codebook,
                peeled_state_low,
                state_high_guess,
                next_stage_table,
                next_state_low_guess,
                high_values,
                low_values,
            )
            if best_score is None or score < best_score:
                best_score = score
                best_next_low = next_state_low_guess
        results.append(
            (
                best_score if best_score is not None else 0,
                best_next_low if best_next_low is not None else 0,
                state_high_guess,
            )
        )
    results.sort()
    return results


def demo_rank_state_high(target_stage: int, sample_highs: int, low_step: int, top: int) -> None:
    if target_stage <= 1:
        raise ValueError("target_stage must be at least 2 so there is a next inner stage to score")

    codebook, true_keypair, true_state = peel_true_outer_stages(target_stage)
    keypairs = [tuple(DEFAULT_KEY[i : i + 2]) for i in range(0, 16, 2)]
    next_keypair = keypairs[target_stage - 2]

    highs = sample_high_values(sample_highs)
    lows = sample_low_values(low_step)

    decoded = decode_output_stage(codebook, target_stage, true_keypair)
    next_stage_table = precompute_dec_table(target_stage - 1, next_keypair)
    results = rank_state_high_candidates(decoded, true_state & 0xFF, next_stage_table, highs, lows)

    print(f"Stage {target_stage} state-high ranking via stage {target_stage - 1}")
    print(f"True stage keypair: {true_keypair[0]:04X}{true_keypair[1]:04X}")
    print(f"True state word: 0x{true_state:04X}")
    for score, next_low, state_high in results[:top]:
        print(f"  score={score:4d}  next_low=0x{next_low:02X}  state_high=0x{state_high:02X}")
    rank = next(i for i, row in enumerate(results, 1) if row[2] == (true_state >> 8))
    print(f"True rank: {rank}/{len(results)}")


def parse_hex_words(words_hex: str, expected_words: int) -> List[int]:
    words_hex = words_hex.strip()
    if words_hex.startswith(("0x", "0X")):
        words_hex = words_hex[2:]
    if len(words_hex) != expected_words * 4:
        raise ValueError(f"expected exactly {expected_words * 4} hex chars")
    return [int(words_hex[i : i + 4], 16) for i in range(0, len(words_hex), 4)]


def main() -> None:
    ap = argparse.ArgumentParser(description="SEPAR stage-peeling attack helpers")
    sub = ap.add_subparsers(dest="mode", required=True)

    build = sub.add_parser("build-codebook", help="build a full first-block codebook from the local DLL/model")
    build.add_argument("--out", required=True, help="output .bin file")
    build.add_argument("--dll", default=str(Path("SEPAR") / "SEPAR.dll"), help="path to SEPAR.dll")
    build.add_argument("--key", help="optional 16-word key hex; defaults to built-in key")
    build.add_argument("--iv", help="optional 8-word IV hex; defaults to zero IV")
    build.add_argument("--use-python-model", action="store_true", help="use the pure-Python model instead of the DLL")

    rank = sub.add_parser("demo-rank", help="validate sampled output-stage ranking against random wrong keys")
    rank.add_argument("--stage", type=int, required=True, choices=range(1, 9), help="target stage number 1..8")
    rank.add_argument("--random-candidates", type=int, default=300, help="number of random wrong keypairs")
    rank.add_argument("--sample-highs", type=int, default=8, help="number of sampled high-byte groups")
    rank.add_argument("--low-step", type=int, default=4, help="sample every Nth low byte")
    rank.add_argument("--seed", type=int, default=0, help="random seed")

    high = sub.add_parser("demo-state-high", help="rank the missing peeled state high byte using the true next-stage key")
    high.add_argument("--stage", type=int, required=True, choices=range(2, 9), help="peeled stage number 2..8")
    high.add_argument("--sample-highs", type=int, default=8, help="number of sampled high-byte groups")
    high.add_argument("--low-step", type=int, default=8, help="sample every Nth low byte")
    high.add_argument("--top", type=int, default=10, help="how many top high-byte candidates to print")

    recover = sub.add_parser("recover-input-low", help="recover an input-side state low byte from a codebook")
    recover.add_argument("--codebook", required=True, help="path to a full 65536-word codebook")
    recover.add_argument("--stage", type=int, required=True, choices=range(1, 9), help="stage number 1..8")
    recover.add_argument("--sample-highs", type=int, default=16, help="number of sampled high-byte groups")
    recover.add_argument("--keypair", default="00000000", help="arbitrary 8-hex-digit keypair for the invariant test")

    score = sub.add_parser("score-range", help="score a key range for an output-side stage search")
    score.add_argument("--codebook", required=True, help="path to a full 65536-word codebook")
    score.add_argument("--stage", type=int, required=True, choices=range(1, 9), help="stage number 1..8")
    score.add_argument("--start-index", type=lambda x: int(x, 0), required=True, help="start key index as int or 0x...")
    score.add_argument("--count", type=lambda x: int(x, 0), required=True, help="number of keypairs to score")
    score.add_argument("--sample-highs", type=int, default=8, help="number of sampled high-byte groups")
    score.add_argument("--low-step", type=int, default=4, help="sample every Nth low byte")
    score.add_argument("--exact", action="store_true", help="use the full exact score instead of a sampled score")
    score.add_argument("--top", type=int, default=10, help="how many top candidates to print")

    args = ap.parse_args()

    if args.mode == "build-codebook":
        key = DEFAULT_KEY if not args.key else parse_hex_words(args.key, 16)
        iv = DEFAULT_IV if not args.iv else parse_hex_words(args.iv, 8)
        out_path = Path(args.out)
        if args.use_python_model:
            codebook = build_first_block_codebook_local(key, iv)
        else:
            codebook = build_first_block_codebook_dll(args.dll, key, iv)
        save_codebook(out_path, codebook)
        print(f"saved {out_path} ({len(codebook)} words)")
        return

    if args.mode == "demo-rank":
        demo_rank_stage(args.stage, args.random_candidates, args.sample_highs, args.low_step, args.seed)
        return

    if args.mode == "demo-state-high":
        demo_rank_state_high(args.stage, args.sample_highs, args.low_step, args.top)
        return

    if args.mode == "recover-input-low":
        codebook = load_codebook(Path(args.codebook))
        keypair = parse_hex_words(args.keypair, 2)
        score_value, low_byte = recover_input_state_low_byte(codebook, args.stage, keypair, args.sample_highs)
        print(f"best_low=0x{low_byte:02X}  score={score_value:.4f}")
        return

    if args.mode == "score-range":
        codebook = load_codebook(Path(args.codebook))
        results = score_key_range(
            codebook,
            args.stage,
            args.start_index,
            args.count,
            args.sample_highs,
            args.low_step,
            args.exact,
        )
        for score_value, index, keypair, low_byte in results[: args.top]:
            print(
                f"score={score_value:8.4f}  index=0x{index:08X}  keypair={keypair[0]:04X}{keypair[1]:04X}  "
                f"best_low=0x{low_byte:02X}"
            )
        return


if __name__ == "__main__":
    main()
