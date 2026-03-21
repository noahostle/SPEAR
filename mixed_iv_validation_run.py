#!/usr/bin/env python3

from __future__ import annotations

import time
from typing import Dict, List, Sequence, Tuple

from recursive_deterministic_recovery import (
    build_first_block_codebook_from_iv,
    recover_inner_stage,
    recover_stage8_from_codebook,
)
from separ_analysis import DEFAULT_IV, DEFAULT_KEY, enc_block, initial_state


MASK16 = 0xFFFF

STAGE_IV7 = {
    8: 0xDA5C,
    7: 0xDA5C,
    6: 0xDA5C,
    5: 0xDA5C,
    4: 0x6E32,
    3: 0x6E32,
    2: 0xDA5C,
    1: 0xDA5C,
}


def true_stage_view(stage: int, iv7: int) -> Tuple[Tuple[int, ...], int, Tuple[int, int]]:
    iv = list(DEFAULT_IV)
    iv[7] = iv7 & MASK16
    ctx = initial_state(DEFAULT_KEY, iv)
    kp = [tuple(DEFAULT_KEY[i : i + 2]) for i in range(0, 16, 2)]

    outputs: List[int] = []
    for pt in range(1 << 16):
        x1 = (pt + ctx.state_1) & MASK16
        v12 = enc_block(x1, kp[0], 1)
        x2 = (v12 + ctx.state_2) & MASK16
        v23 = enc_block(x2, kp[1], 2)
        x3 = (v23 + ctx.state_3) & MASK16
        v34 = enc_block(x3, kp[2], 3)
        x4 = (v34 + ctx.state_4) & MASK16
        v45 = enc_block(x4, kp[3], 4)
        x5 = (v45 + ctx.state_5) & MASK16
        v56 = enc_block(x5, kp[4], 5)
        x6 = (v56 + ctx.state_6) & MASK16
        v67 = enc_block(x6, kp[5], 6)
        x7 = (v67 + ctx.state_7) & MASK16
        v78 = enc_block(x7, kp[6], 7)
        x8 = (v78 + ctx.state_8) & MASK16

        stage_outputs = {
            7: x8,
            6: x7,
            5: x6,
            4: x5,
            3: x4,
            2: x3,
            1: x2,
        }
        outputs.append(stage_outputs[stage])

    next_states = {
        7: ctx.state_8,
        6: ctx.state_7,
        5: ctx.state_6,
        4: ctx.state_5,
        3: ctx.state_4,
        2: ctx.state_3,
        1: ctx.state_2,
    }
    key_pair = kp[stage - 1]
    return tuple(outputs), next_states[stage], key_pair


def fmt_pair(key_pair: Sequence[int]) -> str:
    return f"{key_pair[0]:04X}{key_pair[1]:04X}"


def main() -> None:
    total_start = time.perf_counter()
    print("Mixed-IV validation run")
    print(f"stage IV map: {', '.join(f's{stage}=0x{iv:04X}' for stage, iv in sorted(STAGE_IV7.items(), reverse=True))}")
    print()

    stage_results: Dict[int, Tuple[int, int]] = {}

    stage8_iv = STAGE_IV7[8]
    iv = list(DEFAULT_IV)
    iv[7] = stage8_iv
    t0 = time.perf_counter()
    codebook = build_first_block_codebook_from_iv(iv)
    stage8_branches = recover_stage8_from_codebook(codebook, max_cycles=1)
    dt = time.perf_counter() - t0
    true_stage8 = (DEFAULT_KEY[14], DEFAULT_KEY[15])
    matching_stage8 = [br for br in stage8_branches if br.recovered[-1].key_pair == true_stage8]
    print(f"stage 8 | iv7=0x{stage8_iv:04X} | branches={len(stage8_branches)} | time={dt:.2f}s")
    for br in stage8_branches[:16]:
        print(f"  candidate {fmt_pair(br.recovered[-1].key_pair)}")
    print(f"  contains true key: {bool(matching_stage8)}")
    print()
    stage_results[8] = true_stage8

    for stage in range(7, 0, -1):
        iv7 = STAGE_IV7[stage]
        outputs, next_state, true_key = true_stage_view(stage, iv7)
        t0 = time.perf_counter()
        branches = recover_inner_stage(stage, outputs, low_values=[next_state & 0xFF])
        dt = time.perf_counter() - t0
        matching = [br for br in branches if br.recovered[-1].key_pair == true_key]
        print(
            f"stage {stage} | iv7=0x{iv7:04X} | branches={len(branches)} | "
            f"true_next_state=0x{next_state:04X} | time={dt:.2f}s"
        )
        for br in branches[:16]:
            rec = br.recovered[-1]
            print(f"  candidate {fmt_pair(rec.key_pair)} next_state=0x{rec.next_state_word:04X}")
        if matching:
            rec = matching[0].recovered[-1]
            print(f"  selected true branch: {fmt_pair(rec.key_pair)} next_state=0x{rec.next_state_word:04X}")
            stage_results[stage] = rec.key_pair
        else:
            print(f"  selected true branch: not found")
        print()

    total_dt = time.perf_counter() - total_start
    recovered_words: List[int] = []
    complete = all(stage in stage_results for stage in range(1, 9))
    if complete:
        for stage in range(1, 9):
            recovered_words.extend(stage_results[stage])
    print(f"total time: {total_dt:.2f}s")
    print(f"all stages recovered on this validation path: {complete}")
    if complete:
        print("recovered master key:")
        print("  " + "".join(f"{word:04X}" for word in recovered_words))


if __name__ == "__main__":
    main()
