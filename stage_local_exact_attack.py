#!/usr/bin/env python3

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

from separ_analysis import (
    DEFAULT_IV,
    DEFAULT_KEY,
    SBOX2,
    derive_key2,
    derive_key3,
    enc_block,
    initial_state,
)


MASK16 = 0xFFFF


@dataclass(frozen=True)
class StageLocalRecovery:
    stage: int
    state_word: int
    k0: int
    k1: int


def build_stage_local_codebook(stage: int, state_word: int, key_pair: Sequence[int]) -> List[int]:
    return [enc_block((x + state_word) & MASK16, key_pair, stage) for x in range(1 << 16)]


def build_nib1_function_table() -> Dict[Tuple[int, ...], Tuple[int, int, int, int]]:
    table: Dict[Tuple[int, ...], Tuple[int, int, int, int]] = {}
    for a in range(16):
        for b in range(16):
            for c in range(16):
                for d in range(16):
                    out: List[int] = []
                    for x in range(16):
                        t = SBOX2[x ^ a]
                        t = SBOX2[t ^ b]
                        t = SBOX2[t ^ c]
                        t = SBOX2[t ^ d]
                        t = SBOX2[t ^ a ^ b] ^ c ^ d
                        out.append(t)
                    table[tuple(out)] = (a, b, c, d)
    return table


def build_inverse_maps() -> Tuple[Dict[int, List[int]], Dict[int, List[int]]]:
    inv_k2: Dict[int, List[int]] = defaultdict(list)
    inv_k3: Dict[int, List[int]] = defaultdict(list)
    for low6 in range(64):
        inv_k2[(derive_key2(low6, 8) >> 8) & 0xF].append(low6)
    for bits in range(64):
        k1 = (bits & 0x3) | (((bits >> 2) & 0xF) << 12)
        inv_k3[(derive_key3(k1, 8) >> 8) & 0xF].append(bits)
    return inv_k2, inv_k3


def step1_candidates(
    codebook: Sequence[int],
    nib1_function_table: Dict[Tuple[int, ...], Tuple[int, int, int, int]],
) -> List[Tuple[int, int, int, int, int, int]]:
    rows: List[Tuple[int, ...]] = []
    for low in range(256):
        row = tuple((codebook[low | (hi << 8)] >> 8) & 0xF for hi in range(16))
        rows.append(row)

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
        if row1 is not None:
            if tuple(row0[(i + 1) & 15] for i in range(16)) != row1:
                continue
        for state_hi_low in range(16):
            g = tuple(row0[(x - state_hi_low) & 15] for x in range(16))
            abcd = nib1_function_table.get(g)
            if abcd is not None:
                candidates.append((state_low, state_hi_low, *abcd))
    return candidates


def step2_candidates(
    stage: int,
    codebook: Sequence[int],
    step1: Iterable[Tuple[int, int, int, int, int, int]],
    inv_k2: Dict[int, List[int]],
    inv_k3: Dict[int, List[int]],
) -> List[Tuple[int, int, int, int]]:
    target_nib2 = [((codebook[x] >> 4) & 0xF) for x in range(4096)]
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
                        predicted = (enc_block((x + base_state) & 0x0FFF, (k0, k1), stage) >> 4) & 0xF
                        if predicted != target_nib2[x]:
                            ok = False
                            break
                    if ok:
                        survivors.append((state_low, state_hi_low, k0, k1))
    return survivors


def final_candidates(stage: int, codebook: Sequence[int], step2: Iterable[Tuple[int, int, int, int]]) -> List[StageLocalRecovery]:
    target = list(codebook)
    out: List[StageLocalRecovery] = []
    for state_low, state_hi_low, k0, k1 in step2:
        for state_hi_top in range(16):
            state_word = state_low | (state_hi_low << 8) | (state_hi_top << 12)
            if all(enc_block((x + state_word) & MASK16, (k0, k1), stage) == target[x] for x in range(1 << 16)):
                out.append(StageLocalRecovery(stage, state_word, k0, k1))
    return out


def recover_stage_local(stage: int, codebook: Sequence[int]) -> List[StageLocalRecovery]:
    nib1_function_table = build_nib1_function_table()
    inv_k2, inv_k3 = build_inverse_maps()
    step1 = step1_candidates(codebook, nib1_function_table)
    step2 = step2_candidates(stage, codebook, step1, inv_k2, inv_k3)
    return final_candidates(stage, codebook, step2)


def validate_default_stages() -> None:
    ctx = initial_state(DEFAULT_KEY, DEFAULT_IV)
    states = {
        1: ctx.state_1,
        2: ctx.state_2,
        3: ctx.state_3,
        4: ctx.state_4,
        5: ctx.state_5,
        6: ctx.state_6,
        7: ctx.state_7,
        8: ctx.state_8,
    }
    for stage in range(8, 0, -1):
        key_pair = (DEFAULT_KEY[(stage - 1) * 2], DEFAULT_KEY[(stage - 1) * 2 + 1])
        codebook = build_stage_local_codebook(stage, states[stage], key_pair)
        recovered = recover_stage_local(stage, codebook)
        print(
            f"stage {stage}: recovered {len(recovered)} candidate(s): "
            + ", ".join(
                f"(state={r.state_word:04X}, key={r.k0:04X}{r.k1:04X})"
                for r in recovered
            )
        )


if __name__ == "__main__":
    validate_default_stages()
