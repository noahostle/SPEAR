from __future__ import annotations

import argparse
import ctypes
import random
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

from separ_model import DEFAULT_KEY, enc_block, init_state

MASK16 = 0xFFFF


def load_oracle(dll_path: Path):
    lib = ctypes.CDLL(str(dll_path.resolve()))
    fn = lib.separ_encrypt_words
    fn.argtypes = [
        ctypes.POINTER(ctypes.c_uint16),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint16),
        ctypes.POINTER(ctypes.c_uint16),
        ctypes.POINTER(ctypes.c_uint16),
    ]
    fn.restype = ctypes.c_int
    return fn


def hex_words(hex_text: str, expected_words: int) -> List[int]:
    text = hex_text.strip().removeprefix("0x").removeprefix("0X")
    if len(text) != expected_words * 4:
        raise SystemExit(f"expected exactly {expected_words * 4} hex chars")
    return [int(text[i : i + 4], 16) for i in range(0, len(text), 4)]


def inverse_stage_table(key_pair: Sequence[int], stage_number: int) -> List[int]:
    inv = [0] * 65536
    for x in range(65536):
        inv[enc_block(x, key_pair, stage_number)] = x
    return inv


def dll_second_block_codebook(
    oracle_fn,
    prefix: int,
    iv_words: Sequence[int],
    suffixes: Iterable[int],
) -> Dict[int, int]:
    pt = (ctypes.c_uint16 * 2)()
    ct = (ctypes.c_uint16 * 2)()
    iv = (ctypes.c_uint16 * 8)(*iv_words)
    out: Dict[int, int] = {}
    pt[0] = prefix & MASK16
    for suffix in suffixes:
        pt[1] = suffix & MASK16
        rc = oracle_fn(pt, 2, None, iv, ct)
        if rc != 0:
            raise RuntimeError(f"oracle returned error code {rc}")
        out[suffix] = ct[1]
    return out


def first_intermediates(pt: int, state, key: Sequence[int]) -> Dict[str, int]:
    v12 = enc_block((pt + state.s1) & MASK16, key[0:2], 1)
    v23 = enc_block((v12 + state.s2) & MASK16, key[2:4], 2)
    v34 = enc_block((v23 + state.s3) & MASK16, key[4:6], 3)
    v45 = enc_block((v34 + state.s4) & MASK16, key[6:8], 4)
    v56 = enc_block((v45 + state.s5) & MASK16, key[8:10], 5)
    v67 = enc_block((v56 + state.s6) & MASK16, key[10:12], 6)
    v78 = enc_block((v67 + state.s7) & MASK16, key[12:14], 7)
    ct = enc_block((v78 + state.s8) & MASK16, key[14:16], 8)
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


def second_block_shift_delta_score(
    xa: Dict[int, int],
    xb: Dict[int, int],
    delta: int,
    sample_suffixes: Sequence[int],
    alphas: Sequence[int],
) -> int:
    inv_xb = {value: key for key, value in xb.items()}
    total = 0
    for alpha in alphas:
        counts: Dict[int, int] = {}
        for q in sample_suffixes:
            q_alpha = (q + alpha) & MASK16
            if q_alpha not in xa:
                continue
            y0 = (xa[q] - delta) & MASK16
            y1 = (xa[q_alpha] - delta) & MASK16
            q0 = inv_xb.get(y0)
            q1 = inv_xb.get(y1)
            if q0 is None or q1 is None:
                continue
            diff = (q1 - q0) & MASK16
            counts[diff] = counts.get(diff, 0) + 1
        total += max(counts.values(), default=0)
    return total


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Demonstrate the block-2 stage-8 shift leak: after the K8 peel, the second-block "
            "relative shift between prefixes equals Delta v45(prefix)."
        )
    )
    parser.add_argument("--dll", default="SEPAR/SEPAR.dll", help="Path to the SEPAR DLL")
    parser.add_argument("--iv", default="00000000000000000000000000000000", help="128-bit IV as 32 hex chars")
    parser.add_argument("--prefix-a", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--prefix-b", type=lambda x: int(x, 0), default=1)
    parser.add_argument("--k8", default="FC7D6371", help="Recovered K8 as 8 hex chars")
    parser.add_argument("--sample-size", type=int, default=65536, help="Number of suffixes 0..sample-size-1 to query")
    parser.add_argument("--alphas", default="1,2,3,4,5,6,7,8")
    parser.add_argument("--wrong-count", type=int, default=16, help="Random wrong deltas to compare against")
    parser.add_argument(
        "--verify-model",
        action="store_true",
        help="Also print the true Delta v45 for the built-in default key",
    )
    args = parser.parse_args()

    iv_words = hex_words(args.iv, 8)
    k8_words = hex_words(args.k8, 2)
    alphas = [int(part, 0) & MASK16 for part in args.alphas.split(",") if part]
    suffixes = list(range(args.sample_size))
    need = set(suffixes)
    for alpha in alphas:
        need.update(((q + alpha) & MASK16) for q in suffixes)
    need = sorted(need)

    oracle_fn = load_oracle(Path(args.dll))
    ct2_a = dll_second_block_codebook(oracle_fn, args.prefix_a & MASK16, iv_words, need)
    ct2_b = dll_second_block_codebook(oracle_fn, args.prefix_b & MASK16, iv_words, need)

    inv8 = inverse_stage_table(k8_words, 8)
    x8_a = {q: inv8[ct] for q, ct in ct2_a.items()}
    x8_b = {q: inv8[ct] for q, ct in ct2_b.items()}

    rng = random.Random(1)
    guesses: List[int] = []
    true_delta = None
    if args.verify_model:
        state = init_state(DEFAULT_KEY, iv_words)
        ints_a = first_intermediates(args.prefix_a & MASK16, state, DEFAULT_KEY)
        ints_b = first_intermediates(args.prefix_b & MASK16, state, DEFAULT_KEY)
        true_delta = (ints_a["v45"] - ints_b["v45"]) & MASK16
        guesses.append(true_delta)

    while len(guesses) < (args.wrong_count + (1 if true_delta is not None else 0)):
        candidate = rng.randrange(1 << 16)
        if candidate not in guesses:
            guesses.append(candidate)

    scored = [
        (delta, second_block_shift_delta_score(x8_a, x8_b, delta, suffixes, alphas))
        for delta in guesses
    ]
    scored.sort(key=lambda item: item[1], reverse=True)

    print(f"[+] prefixes: {args.prefix_a & MASK16:04X} vs {args.prefix_b & MASK16:04X}")
    print(f"[+] queried {len(need)} suffix values for each prefix")
    print(f"[+] K8 used for the peel: {k8_words[0]:04X}{k8_words[1]:04X}")
    if true_delta is not None:
        rank = next(i for i, item in enumerate(scored, start=1) if item[0] == true_delta)
        print(f"[+] true Delta v45 = {true_delta:04X}  rank={rank}  score={dict(scored)[true_delta]}")
    print("[+] top scored deltas:")
    for delta, score in scored[:10]:
        marker = "  <-- true" if true_delta is not None and delta == true_delta else ""
        print(f"    {delta:04X}  score={score}{marker}")


if __name__ == "__main__":
    main()
