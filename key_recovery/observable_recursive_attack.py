#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

from recursive_deterministic_recovery import (
    Branch,
    StageRecovery,
    build_first_block_codebook_from_iv,
    recover_inner_stage,
    recover_stage8_from_codebook,
)
from separ_analysis import DEFAULT_IV, MASK16, dec_block


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

_WORK_STAGE: int | None = None
_WORK_OUTPUTS: Tuple[int, ...] | None = None


@dataclass(frozen=True)
class ObservableBranch:
    outputs_by_iv: Mapping[int, Tuple[int, ...]]
    recovered: Tuple[StageRecovery, ...]


def fmt_pair(key_pair: Sequence[int]) -> str:
    return f"{key_pair[0]:04X}{key_pair[1]:04X}"


def unique_ivs(stage_iv_map: Mapping[int, int]) -> List[int]:
    return sorted({iv7 & MASK16 for iv7 in stage_iv_map.values()})


def build_codebooks_for_ivs(iv_values: Iterable[int]) -> Dict[int, Tuple[int, ...]]:
    out: Dict[int, Tuple[int, ...]] = {}
    for iv7 in iv_values:
        iv = list(DEFAULT_IV)
        iv[7] = iv7 & MASK16
        out[iv7 & MASK16] = tuple(build_first_block_codebook_from_iv(iv))
    return out


def peel_stage_outputs(
    outputs: Sequence[int],
    stage: int,
    key_pair: Tuple[int, int],
    next_state_word: int | None,
) -> Tuple[int, ...]:
    if next_state_word is None:
        return tuple(dec_block(value, key_pair, stage) for value in outputs)
    return tuple(dec_block((value - next_state_word) & MASK16, key_pair, stage) for value in outputs)


def seed_stage8_branches(
    codebooks_by_iv: Mapping[int, Tuple[int, ...]],
    stage8_iv: int,
    max_cycles: int | None = None,
) -> List[ObservableBranch]:
    stage8_branches = recover_stage8_from_codebook(codebooks_by_iv[stage8_iv], max_cycles=max_cycles)
    out: List[ObservableBranch] = []
    for branch in stage8_branches:
        rec = branch.recovered[-1]
        peeled: Dict[int, Tuple[int, ...]] = {}
        for iv7, codebook in codebooks_by_iv.items():
            if iv7 == stage8_iv:
                peeled[iv7] = branch.outputs
            else:
                peeled[iv7] = peel_stage_outputs(codebook, 8, rec.key_pair, None)
        out.append(ObservableBranch(peeled, branch.recovered))
    return out


def _init_recover_worker(stage: int, outputs: Tuple[int, ...]) -> None:
    global _WORK_STAGE, _WORK_OUTPUTS
    _WORK_STAGE = stage
    _WORK_OUTPUTS = outputs


def _recover_low_worker(low: int) -> List[StageRecovery]:
    assert _WORK_STAGE is not None
    assert _WORK_OUTPUTS is not None
    local = recover_inner_stage(_WORK_STAGE, _WORK_OUTPUTS, low_values=[low & 0xFF])
    return [branch.recovered[-1] for branch in local]


def recover_stage_candidates_honest(
    stage: int,
    outputs: Sequence[int],
    workers: int,
    progress_every: int = 16,
) -> List[StageRecovery]:
    start = time.perf_counter()
    workers = max(1, workers)
    outputs_tuple = tuple(outputs)
    found: Dict[Tuple[int, int, int], StageRecovery] = {}
    lows_done = 0

    if workers == 1:
        _init_recover_worker(stage, outputs_tuple)
        for low in range(256):
            for rec in _recover_low_worker(low):
                found[(rec.key_pair[0], rec.key_pair[1], rec.next_state_word or -1)] = rec
            lows_done += 1
            if lows_done % progress_every == 0 or lows_done == 256:
                dt = time.perf_counter() - start
                print(
                    f"    stage {stage}: low search {lows_done}/256, "
                    f"candidates={len(found)}, elapsed={dt:.2f}s"
                )
    else:
        with ProcessPoolExecutor(
            max_workers=workers,
            initializer=_init_recover_worker,
            initargs=(stage, outputs_tuple),
        ) as ex:
            future_map = {ex.submit(_recover_low_worker, low): low for low in range(256)}
            for future in as_completed(future_map):
                low = future_map[future]
                for rec in future.result():
                    found[(rec.key_pair[0], rec.key_pair[1], rec.next_state_word or -1)] = rec
                lows_done += 1
                if lows_done % progress_every == 0 or lows_done == 256:
                    dt = time.perf_counter() - start
                    print(
                        f"    stage {stage}: low search {lows_done}/256, "
                        f"candidates={len(found)}, elapsed={dt:.2f}s"
                    )
    return list(found.values())


def extend_observable_branch(
    branch: ObservableBranch,
    stage: int,
    stage_iv_map: Mapping[int, int],
    workers: int,
) -> List[ObservableBranch]:
    iv7 = stage_iv_map[stage] & MASK16
    outputs = branch.outputs_by_iv[iv7]
    local_candidates = recover_stage_candidates_honest(stage, outputs, workers=workers)
    out: List[ObservableBranch] = []
    for rec in local_candidates:
        peeled: Dict[int, Tuple[int, ...]] = {}
        for codebook_iv7, codebook in branch.outputs_by_iv.items():
            peeled[codebook_iv7] = peel_stage_outputs(codebook, stage, rec.key_pair, rec.next_state_word)
        out.append(ObservableBranch(peeled, branch.recovered + (rec,)))
    return out


def recover_observable_prefix(
    stop_after: int,
    max_stage8_cycles: int | None,
    stage8_branch_limit: int | None,
    workers: int,
) -> List[ObservableBranch]:
    stage8_iv = STAGE_IV7[8]
    codebooks = build_codebooks_for_ivs(unique_ivs(STAGE_IV7))
    print(
        "built first-block codebooks for iv7 values: "
        + ", ".join(f"0x{iv7:04X}" for iv7 in sorted(codebooks))
    )

    t0 = time.perf_counter()
    live = seed_stage8_branches(codebooks, stage8_iv=stage8_iv, max_cycles=max_stage8_cycles)
    dt = time.perf_counter() - t0
    print(f"stage 8 seeded {len(live)} branch(es) in {dt:.2f}s")
    for idx, branch in enumerate(live):
        rec = branch.recovered[-1]
        print(f"  s8 branch {idx}: key={fmt_pair(rec.key_pair)}")

    if stage8_branch_limit is not None:
        live = live[:stage8_branch_limit]
        print(f"limiting stage-8 parents to the first {len(live)} branch(es) for this run")

    for stage in range(7, stop_after - 1, -1):
        next_live: List[ObservableBranch] = []
        stage_start = time.perf_counter()
        print(f"stage {stage}: expanding {len(live)} parent branch(es) with iv7=0x{STAGE_IV7[stage]:04X}")
        for idx, branch in enumerate(live):
            print(f"  parent {idx}: recovered {[fmt_pair(item.key_pair) for item in branch.recovered]}")
            children = extend_observable_branch(branch, stage, STAGE_IV7, workers=workers)
            print(f"  parent {idx}: produced {len(children)} child branch(es)")
            for child_index, child in enumerate(children[:16]):
                rec = child.recovered[-1]
                print(
                    f"    child {child_index}: stage {stage}, key={fmt_pair(rec.key_pair)}, "
                    f"next_state=0x{rec.next_state_word:04X}"
                )
            next_live.extend(children)
        live = next_live
        dt = time.perf_counter() - stage_start
        print(f"after stage {stage}: {len(live)} live branch(es), elapsed={dt:.2f}s")
        if not live:
            break
    return live


def main() -> None:
    ap = argparse.ArgumentParser(description="Observable-only recursive SEPAR attack prototype.")
    ap.add_argument("--stop-after", type=int, default=7, help="deepest stage to recover in this run")
    ap.add_argument(
        "--max-stage8-cycles",
        type=int,
        default=1,
        help="limit the number of raw stage-8 low-group cycles to extend",
    )
    ap.add_argument(
        "--stage8-branch-limit",
        type=int,
        default=1,
        help="limit how many stage-8 candidate keys to follow for timing tests",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=min(16, (os.cpu_count() or 1)),
        help="number of worker processes for the inner low-byte search",
    )
    args = ap.parse_args()

    total_start = time.perf_counter()
    print("Observable-only recursive run")
    print(
        "stage IV map: "
        + ", ".join(f"s{stage}=0x{iv7:04X}" for stage, iv7 in sorted(STAGE_IV7.items(), reverse=True))
    )
    print(f"workers: {args.workers}")
    print()

    live = recover_observable_prefix(
        stop_after=args.stop_after,
        max_stage8_cycles=args.max_stage8_cycles,
        stage8_branch_limit=args.stage8_branch_limit,
        workers=args.workers,
    )

    total_dt = time.perf_counter() - total_start
    print()
    print(f"total time: {total_dt:.2f}s")
    print(f"live branches after stage {args.stop_after}: {len(live)}")
    for idx, branch in enumerate(live[:16]):
        print(f"  branch {idx}: {[fmt_pair(item.key_pair) for item in branch.recovered]}")


if __name__ == "__main__":
    main()
