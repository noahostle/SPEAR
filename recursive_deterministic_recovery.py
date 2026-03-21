#!/usr/bin/env python3

from __future__ import annotations

import argparse
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

from recursive_quotient_attack import reconstruct_order_from_outputs, transition_counts_on_high
from separ_analysis import DEFAULT_IV, DEFAULT_KEY, MASK16, dec_block, enc_block, encrypt_word, initial_state
from weak_iv_transition_bridge import exact_best_matching, precompute_group_matchings


SAMPLE_POSITIONS = (0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 200, 233, 255)

P_INVISIBLE_BITS: Dict[int, Tuple[int, ...]] = {
    1: (),
    2: (0, 1, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23),
    3: (0, 1, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23),
    4: (6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23),
    5: (0, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23),
    6: (0, 1, 2, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23),
    7: (0, 1, 2, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23),
    8: (0, 1, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23, 29),
}


@dataclass(frozen=True)
class StageRecovery:
    stage: int
    key_pair: Tuple[int, int]
    next_state_word: int | None
    observed_cycle: Tuple[int, ...]
    quotient_order: Tuple[int, ...]


@dataclass(frozen=True)
class Branch:
    outputs: Tuple[int, ...]
    recovered: Tuple[StageRecovery, ...]


def build_first_block_codebook_from_iv(iv: Sequence[int]) -> List[int]:
    out = [0] * (1 << 16)
    for pt in range(1 << 16):
        ctx = initial_state(DEFAULT_KEY, iv)
        out[pt] = encrypt_word(pt, ctx, DEFAULT_KEY)
    return out


def canon_cycle(seq: Iterable[int]) -> Tuple[int, ...]:
    out = list(seq)
    if 0 in out:
        idx = out.index(0)
        out = out[idx:] + out[:idx]
    return tuple(out)


def rotate_top_order(order: Sequence[int], r: int) -> Tuple[int, ...]:
    return tuple(order[((top - r) & 0xF) * 16 + low] for top in range(16) for low in range(16))


def build_rotated_order_targets(order: Sequence[int]) -> List[Tuple[int, ...]]:
    return [rotate_top_order(order, r) for r in range(16)]


def quotient_high(key_pair: Tuple[int, int], stage: int, h: int) -> int:
    return (enc_block(h << 8, key_pair, stage) >> 8) & 0xFF


@lru_cache(maxsize=None)
def sample_targets_for_order(order: Tuple[int, ...]) -> List[Tuple[int, ...]]:
    rotated = build_rotated_order_targets(order)
    return [tuple(rot[h] for h in SAMPLE_POSITIONS) for rot in rotated]


def order_target_maps(
    order_infos: Sequence[Tuple[Tuple[int, ...], Tuple[int, ...]]]
) -> Tuple[Dict[Tuple[int, ...], List[Tuple[Tuple[int, ...], Tuple[int, ...]]]], Dict[Tuple[int, ...], Tuple[int, ...]]]:
    sample_map: Dict[Tuple[int, ...], List[Tuple[Tuple[int, ...], Tuple[int, ...]]]] = {}
    target_to_cycle: Dict[Tuple[int, ...], Tuple[int, ...]] = {}
    for cycle, order in order_infos:
        full_targets = build_rotated_order_targets(order)
        sample_targets = sample_targets_for_order(order)
        for sample_target, full_target in zip(sample_targets, full_targets):
            sample_map.setdefault(sample_target, []).append((full_target, cycle))
            target_to_cycle[full_target] = cycle
    return sample_map, target_to_cycle


def observed_low_groups() -> List[Tuple[int, ...]]:
    return [tuple((hi << 4) | lo for hi in range(16)) for lo in range(16)]


def best_group_cycle(outputs: Sequence[int]) -> Tuple[int, Tuple[int, ...]]:
    weights = transition_counts_on_high(outputs, delta=1)
    pair_scores, _ = precompute_group_matchings(weights)
    start = 0
    count = 16

    @lru_cache(maxsize=None)
    def dp(mask: int, last: int) -> Tuple[int, Tuple[int, ...]]:
        if mask == (1 << count) - 1:
            return pair_scores[(last, start)], (start,)
        best_score = -1
        best_path: Tuple[int, ...] | None = None
        for nxt in range(count):
            if (mask >> nxt) & 1:
                continue
            tail_score, tail = dp(mask | (1 << nxt), nxt)
            score = pair_scores[(last, nxt)] + tail_score
            if score > best_score:
                best_score = score
                best_path = (nxt,) + tail
        assert best_path is not None
        return best_score, best_path

    score, path = dp(1 << start, start)
    return score, canon_cycle((start,) + path[:-1])


@lru_cache(maxsize=None)
def projected_p_representatives_raw(stage: int) -> Tuple[Tuple[int, ...], Dict[Tuple[int, ...], Tuple[Tuple[int, int], ...]]]:
    invisible = P_INVISIBLE_BITS[stage]
    visible = tuple(bit for bit in range(32) if bit not in invisible)
    reps: Dict[Tuple[int, ...], List[Tuple[int, int]]] = {}
    for mask in range(1 << len(visible)):
        k0 = 0
        k1 = 0
        for i, bit in enumerate(visible):
            if ((mask >> i) & 1) == 0:
                continue
            if bit < 16:
                k0 |= 1 << bit
            else:
                k1 |= 1 << (bit - 16)
        p = tuple(quotient_high((k0, k1), stage, lo) & 0xF for lo in range(16))
        reps.setdefault(p, []).append((k0, k1))
    frozen = {p: tuple(v) for p, v in reps.items()}
    return visible, frozen


@lru_cache(maxsize=None)
def projected_p_representatives_canonical(stage: int) -> Tuple[Tuple[int, ...], Dict[Tuple[int, ...], Tuple[Tuple[int, int], ...]]]:
    visible, raw = projected_p_representatives_raw(stage)
    out: Dict[Tuple[int, ...], List[Tuple[int, int]]] = {}
    for p, reps in raw.items():
        out.setdefault(canon_cycle(p), []).extend(reps)
    frozen = {p: tuple(v) for p, v in out.items()}
    return visible, frozen


def exact_stage_key_candidates(
    stage: int,
    order_infos: Sequence[Tuple[Tuple[int, ...], Sequence[int]]],
    observed_cycle: Sequence[int],
    allow_translation: bool,
) -> List[Tuple[Tuple[int, int], int, Tuple[int, ...]]]:
    normalized_infos = [(tuple(cycle), tuple(order)) for cycle, order in order_infos]
    sample_map, _target_to_cycle = order_target_maps(normalized_infos)
    invisible = P_INVISIBLE_BITS[stage]
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

    if allow_translation:
        _, rep_map = projected_p_representatives_canonical(stage)
        tl_values = range(16)
    else:
        _, rep_map = projected_p_representatives_raw(stage)
        tl_values = range(1)
    seen: set[Tuple[int, int, int, Tuple[int, ...]]] = set()
    out: List[Tuple[Tuple[int, int], int, Tuple[int, ...]]] = []
    for tl in tl_values:
        projected = (
            canon_cycle(((value - tl) & 0xF) for value in observed_cycle)
            if allow_translation
            else tuple(observed_cycle)
        )
        base_keys = rep_map.get(projected, ())
        if not base_keys:
            continue
        for base_k0, base_k1 in base_keys:
            for add_k0, add_k1 in invisible_masks:
                k0 = base_k0 | add_k0
                k1 = base_k1 | add_k1
                sample_q = [quotient_high((k0, k1), stage, h) for h in SAMPLE_POSITIONS]
                for tau_hi in range(16):
                    tau = (tau_hi << 4) | tl
                    shifted = tuple((value + tau) & 0xFF for value in sample_q)
                    matching_infos = sample_map.get(shifted)
                    if matching_infos:
                        break
                else:
                    continue
                full_q = tuple(quotient_high((k0, k1), stage, h) for h in range(256))
                shifted_full = tuple((value + tau) & 0xFF for value in full_q)
                for full_target, _cycle in sample_map.get(shifted, ()):
                    if shifted_full != full_target:
                        continue
                    key = (k0, k1, tau, full_target)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(((k0, k1), tau, full_target))
    return out


def recover_stage8_from_codebook(codebook: Sequence[int], max_cycles: int | None = None) -> List[Branch]:
    ct_outputs = tuple(codebook)
    high_weights = transition_counts_on_high(ct_outputs, delta=1)
    pair_scores, _ = precompute_group_matchings(high_weights)
    _, rep_map = projected_p_representatives_raw(8)
    ranked_cycles = sorted(
        rep_map.keys(),
        key=lambda cyc: sum(pair_scores[(cyc[i], cyc[(i + 1) & 0xF])] for i in range(16)),
        reverse=True,
    )

    branches: List[Branch] = []
    for cycle_index, cycle in enumerate(ranked_cycles):
        if max_cycles is not None and cycle_index >= max_cycles:
            break
        order = reconstruct_order_from_outputs(ct_outputs, cycle)
        if order is None:
            continue
        exact = exact_stage_key_candidates(8, [(tuple(cycle), order)], cycle, allow_translation=False)
        if not exact:
            continue
        for key_pair, _tau, _target_order in exact:
            x8 = tuple(dec_block(ct, key_pair, 8) for ct in ct_outputs)
            rec = StageRecovery(8, key_pair, None, tuple(cycle), tuple(order))
            branches.append(Branch(x8, (rec,)))
    return branches


def recover_inner_stage(stage: int, outputs: Sequence[int], low_values: Iterable[int] | None = None) -> List[Branch]:
    if low_values is None:
        low_values = range(256)
    out: List[Branch] = []
    for low in low_values:
        corrected = tuple((value - low) & MASK16 for value in outputs)
        _score, cycle = best_group_cycle(corrected)
        order_infos: List[Tuple[Tuple[int, ...], Tuple[int, ...]]] = []
        cycle_variants = [cycle, tuple([cycle[0]] + list(reversed(cycle[1:])))]
        seen_cycles: set[Tuple[int, ...]] = set()
        for variant in cycle_variants:
            for shift in range(16):
                rotated_cycle = tuple(variant[(i + shift) & 0xF] for i in range(16))
                if rotated_cycle in seen_cycles:
                    continue
                seen_cycles.add(rotated_cycle)
                order = reconstruct_order_from_outputs(corrected, rotated_cycle)
                if order is None:
                    continue
                order_infos.append((rotated_cycle, tuple(order)))
        if not order_infos:
            continue
        grouped: Dict[Tuple[int, ...], List[Tuple[Tuple[int, ...], Tuple[int, ...]]]] = {}
        for cycle_value, order in order_infos:
            grouped.setdefault(canon_cycle(cycle_value), []).append((cycle_value, order))
        seen_local: set[Tuple[int, int, int]] = set()
        for group_key, group_infos in grouped.items():
            exact = exact_stage_key_candidates(stage, group_infos, group_key, allow_translation=True)
            if not exact:
                continue
            target_to_cycle = {}
            for cycle_value, order in group_infos:
                for full_target in build_rotated_order_targets(order):
                    target_to_cycle[full_target] = cycle_value
            for key_pair, tau, target_order in exact:
                local_key = (key_pair[0], key_pair[1], tau)
                if local_key in seen_local:
                    continue
                seen_local.add(local_key)
                next_state = low | (tau << 8)
                stripped = tuple((value - next_state) & MASK16 for value in outputs)
                prev_outputs = tuple(dec_block(value, key_pair, stage) for value in stripped)
                rec = StageRecovery(stage, key_pair, next_state, target_to_cycle[target_order], target_order)
                out.append(Branch(prev_outputs, (rec,)))
    return out


def candidate_master_key(branch: Branch) -> Tuple[int, ...]:
    stage_to_key: Dict[int, Tuple[int, int]] = {item.stage: item.key_pair for item in branch.recovered}
    words: List[int] = []
    for stage in range(1, 9):
        k0, k1 = stage_to_key[stage]
        words.extend((k0, k1))
    return tuple(words)


def validate_master_key(candidate_key: Sequence[int], iv: Sequence[int], codebook: Sequence[int]) -> bool:
    for pt, expected in enumerate(codebook):
        ctx = initial_state(candidate_key, iv)
        if encrypt_word(pt, ctx, candidate_key) != expected:
            return False
    return True


def extend_branch(branch: Branch, stage: int, low_values: Iterable[int] | None = None) -> List[Branch]:
    extensions = recover_inner_stage(stage, branch.outputs, low_values=low_values)
    out: List[Branch] = []
    for ext in extensions:
        out.append(Branch(ext.outputs, branch.recovered + ext.recovered))
    return out


def recover_full_key(iv7: int, stop_after: int = 1, max_stage8_cycles: int | None = None, low_values: Iterable[int] | None = None) -> List[Tuple[int, ...]]:
    iv = list(DEFAULT_IV)
    iv[7] = iv7 & MASK16
    codebook = build_first_block_codebook_from_iv(iv)

    stage8_branches = recover_stage8_from_codebook(codebook, max_cycles=max_stage8_cycles)
    print(f"after stage 8: {len(stage8_branches)} live branch(es)")
    for idx, branch in enumerate(stage8_branches[:8]):
        last = branch.recovered[-1]
        print(f"  branch {idx}: stage 8, key={last.key_pair[0]:04X}{last.key_pair[1]:04X}")

    live = stage8_branches
    for stage in range(7, stop_after - 1, -1):
        next_live: List[Branch] = []
        for branch in live:
            next_live.extend(extend_branch(branch, stage, low_values=low_values))
        live = next_live
        print(f"after stage {stage}: {len(live)} live branch(es)")
        for idx, branch in enumerate(live[:8]):
            last = branch.recovered[-1]
            print(
                f"  branch {idx}: stage {last.stage}, key={last.key_pair[0]:04X}{last.key_pair[1]:04X}, "
                f"next_state={('----' if last.next_state_word is None else f'{last.next_state_word:04X}')}"
            )
        if not live:
            break

    exact: List[Tuple[int, ...]] = []
    if stop_after == 1:
        for branch in live:
            if len(branch.recovered) != 8:
                continue
            key = candidate_master_key(branch)
            if validate_master_key(key, iv, codebook):
                exact.append(key)
    return exact


def main() -> None:
    ap = argparse.ArgumentParser(description="Deterministic recursive quotient-based SEPAR recovery prototype.")
    ap.add_argument("--iv7", type=lambda x: int(x, 0), default=0xDA5C, help="chosen IV word 7, default 0xDA5C")
    ap.add_argument("--stop-after", type=int, default=7, help="deepest stage to recover, default 7")
    ap.add_argument("--max-stage8-cycles", type=int, default=8, help="limit outer stage-8 branches for experiments")
    ap.add_argument("--low-values", type=str, default=None, help="comma-separated low-byte guesses to try at every inner stage")
    args = ap.parse_args()

    low_values = None
    if args.low_values:
        low_values = [int(piece, 0) & 0xFF for piece in args.low_values.split(",") if piece.strip()]

    recovered = recover_full_key(
        args.iv7,
        stop_after=args.stop_after,
        max_stage8_cycles=args.max_stage8_cycles,
        low_values=low_values,
    )
    if recovered:
        print("validated full master key candidate(s):")
        for key in recovered:
            print("  " + "".join(f"{word:04X}" for word in key))


if __name__ == "__main__":
    main()
