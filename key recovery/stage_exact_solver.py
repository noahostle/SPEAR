from __future__ import annotations

import argparse
import time
from typing import List, Sequence, Tuple

import z3

from separ_model import SBOX1, SBOX2, SBOX3, SBOX4

MASK16 = 0xFFFF


def bv16(value: int) -> z3.BitVecRef:
    return z3.BitVecVal(value & MASK16, 16)


def parse_pairs(text: str) -> List[Tuple[int, int]]:
    pairs: List[Tuple[int, int]] = []
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        left, right = chunk.split(":")
        pairs.append((int(left, 0) & MASK16, int(right, 0) & MASK16))
    if not pairs:
        raise SystemExit("at least one input:output pair is required")
    return pairs


def sbox_nibble(x4: z3.BitVecRef, table: Sequence[int]) -> z3.BitVecRef:
    expr = z3.BitVecVal(table[0], 4)
    for index in range(1, 16):
        expr = z3.If(x4 == index, z3.BitVecVal(table[index], 4), expr)
    return expr


def do_sbox(x: z3.BitVecRef) -> z3.BitVecRef:
    return z3.Concat(
        sbox_nibble(z3.Extract(15, 12, x), SBOX1),
        sbox_nibble(z3.Extract(11, 8, x), SBOX2),
        sbox_nibble(z3.Extract(7, 4, x), SBOX3),
        sbox_nibble(z3.Extract(3, 0, x), SBOX4),
    )


def sep_rotl16(x: z3.BitVecRef) -> z3.BitVecRef:
    a = z3.Extract(15, 12, x)
    b = z3.Extract(11, 8, x)
    c = z3.Extract(7, 4, x)
    d = z3.Extract(3, 0, x)

    a2 = a ^ c
    b2 = b ^ d
    c2 = c ^ b2
    d2 = d ^ a2

    mixed = z3.Concat(a2, b2, c2, d2)
    return z3.Extract(15, 0, mixed ^ z3.RotateLeft(mixed, 12) ^ z3.RotateLeft(mixed, 8))


def enc_block_expr(pt: z3.BitVecRef, key0: z3.BitVecRef, key1: z3.BitVecRef, stage: int) -> z3.BitVecRef:
    key2 = z3.RotateLeft(key0, 6)
    key2 = key2 | (z3.ZeroExt(12, sbox_nibble(z3.Extract(9, 6, key2), SBOX1)) << 6)
    key2 = z3.Extract(15, 0, key2 ^ bv16(stage + 2))

    key3 = z3.RotateLeft(key1, 10)
    key3 = key3 | (z3.ZeroExt(12, sbox_nibble(z3.Extract(9, 6, key3), SBOX1)) << 6)
    key3 = z3.Extract(15, 0, key3 ^ bv16(stage + 3))

    t = pt ^ key0
    t = sep_rotl16(do_sbox(t))

    t = t ^ key1
    t = sep_rotl16(do_sbox(t))

    t = t ^ key2
    t = sep_rotl16(do_sbox(t))

    t = t ^ key3
    t = sep_rotl16(do_sbox(t))

    t = t ^ (key0 ^ key1)
    t = do_sbox(t)
    t = z3.Extract(15, 0, t ^ (key2 ^ key3))
    return t


def solve_stage(
    stage: int,
    pairs: Sequence[Tuple[int, int]],
    solve_input_shift: bool,
    solve_output_shift: bool,
    timeout_ms: int,
):
    key0 = z3.BitVec("key0", 16)
    key1 = z3.BitVec("key1", 16)
    input_shift = z3.BitVec("input_shift", 16) if solve_input_shift else bv16(0)
    output_shift = z3.BitVec("output_shift", 16) if solve_output_shift else bv16(0)

    solver = z3.SolverFor("QF_BV")
    solver.set(timeout=timeout_ms)

    for plain, cipher in pairs:
        value = enc_block_expr(bv16(plain) + input_shift, key0, key1, stage)
        solver.add(z3.Extract(15, 0, value + output_shift) == bv16(cipher))

    start = time.perf_counter()
    result = solver.check()
    elapsed = time.perf_counter() - start

    if result != z3.sat:
        return result, elapsed, None

    model = solver.model()
    recovered = {
        "key0": model.eval(key0).as_long() & MASK16,
        "key1": model.eval(key1).as_long() & MASK16,
    }
    if solve_input_shift:
        recovered["input_shift"] = model.eval(input_shift).as_long() & MASK16
    if solve_output_shift:
        recovered["output_shift"] = model.eval(output_shift).as_long() & MASK16
    return result, elapsed, recovered


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Recover one 32-bit SEPAR stage segment from exact 16-bit input/output pairs. "
            "This is the exact-solve step used once a recursive peel has isolated a stage."
        )
    )
    parser.add_argument("--stage", type=int, required=True, help="Stage number 1..8")
    parser.add_argument(
        "--pairs",
        required=True,
        help="Comma-separated input:output words, for example 0x1234:0xABCD,0x2222:0xEEEE",
    )
    parser.add_argument("--solve-input-shift", action="store_true", help="Add one common modular input shift")
    parser.add_argument("--solve-output-shift", action="store_true", help="Add one common modular output shift")
    parser.add_argument("--timeout-ms", type=int, default=60000)
    args = parser.parse_args()

    result, elapsed, recovered = solve_stage(
        args.stage,
        parse_pairs(args.pairs),
        args.solve_input_shift,
        args.solve_output_shift,
        args.timeout_ms,
    )

    print(f"[+] solver result: {result}")
    print(f"[+] elapsed: {elapsed:.3f}s")
    if recovered is None:
        return
    print(f"[+] key pair: {recovered['key0']:04X}{recovered['key1']:04X}")
    if "input_shift" in recovered:
        print(f"[+] input shift:  {recovered['input_shift']:04X}")
    if "output_shift" in recovered:
        print(f"[+] output shift: {recovered['output_shift']:04X}")


if __name__ == "__main__":
    main()
