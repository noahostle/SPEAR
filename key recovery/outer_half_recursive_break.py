from __future__ import annotations

import argparse
import ctypes
import struct
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

from separ_model import enc_block
from stage_exact_solver import solve_stage

MASK16 = 0xFFFF
SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "data"


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
    return [int(text[index : index + 4], 16) for index in range(0, len(text), 4)]


def resolve_data_path(path_text: str) -> Path:
    path = Path(path_text)
    if not path.is_absolute():
        path = DATA_DIR / path
    return path


def inverse_stage_table(key_pair: Sequence[int], stage_number: int) -> List[int]:
    inv = [0] * 65536
    for value in range(65536):
        inv[enc_block(value, key_pair, stage_number)] = value
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


def write_codebook(path: Path, codebook: Dict[int, int]) -> None:
    inputs = sorted(codebook)
    outputs = [codebook[value] for value in inputs]
    with path.open("wb") as handle:
        handle.write(struct.pack("<I", len(inputs)))
        handle.write(struct.pack(f"<{len(inputs)}H", *inputs))
        handle.write(struct.pack(f"<{len(outputs)}H", *outputs))


def read_codebook(path: Path) -> Dict[int, int]:
    data = path.read_bytes()
    count = struct.unpack_from("<I", data, 0)[0]
    inputs = struct.unpack_from(f"<{count}H", data, 4)
    outputs = struct.unpack_from(f"<{count}H", data, 4 + (2 * count))
    return dict(zip(inputs, outputs))


def align_codebook(book: Dict[int, int], delta: int) -> Dict[int, int]:
    return {key: (value - delta) & MASK16 for key, value in book.items()}


def decode_codebook(book: Dict[int, int], inv_table: Sequence[int], shift: int) -> Dict[int, int]:
    return {key: inv_table[(value - shift) & MASK16] for key, value in book.items()}


def run_delta_search(delta_tool: Path, left_path: Path, right_path: Path) -> int:
    out = subprocess.check_output([str(delta_tool), str(left_path), str(right_path)], text=True).strip().split()
    return int(out[0])


def run_scan_shift(search_tool: Path, stage: int, key_pair: Sequence[int], paths: Sequence[Path]) -> tuple[int, int]:
    out = subprocess.check_output(
        [str(search_tool), "scan_shift", str(stage), str(key_pair[0]), str(key_pair[1]), *map(str, paths)],
        text=True,
    ).strip().split()
    return int(out[0]), int(out[1])


def run_scan_k0(search_tool: Path, stage: int, shift: int, key1: int, paths: Sequence[Path]) -> tuple[int, int]:
    out = subprocess.check_output(
        [str(search_tool), "scan_k0", str(stage), str(shift), str(key1), *map(str, paths)],
        text=True,
    ).strip().split()
    return int(out[0]), int(out[1])


def run_scan_k1(search_tool: Path, stage: int, shift: int, key0: int, paths: Sequence[Path]) -> tuple[int, int]:
    out = subprocess.check_output(
        [str(search_tool), "scan_k1", str(stage), str(shift), str(key0), *map(str, paths)],
        text=True,
    ).strip().split()
    return int(out[0]), int(out[1])


def build_stage_paths(
    work_dir: Path,
    stage_label: str,
    prefixes: Sequence[int],
    source_paths: Dict[int, Path],
    inv_table: Sequence[int],
    common_shift: int,
    delta_tool: Path,
) -> tuple[Dict[int, Path], Dict[int, int], List[Path]]:
    ref = prefixes[0]
    raw_paths: Dict[int, Path] = {}
    for prefix in prefixes:
        decoded = decode_codebook(read_codebook(source_paths[prefix]), inv_table, common_shift)
        path = work_dir / f"{stage_label}_raw_{prefix:04X}_{common_shift:04X}.bin"
        write_codebook(path, decoded)
        raw_paths[prefix] = path

    deltas = {ref: 0}
    for prefix in prefixes[1:]:
        deltas[prefix] = run_delta_search(delta_tool, raw_paths[ref], raw_paths[prefix])

    aligned_paths: List[Path] = []
    for prefix in prefixes:
        aligned = align_codebook(read_codebook(raw_paths[prefix]), deltas[prefix])
        path = work_dir / f"{stage_label}_aligned_{prefix:04X}_{common_shift:04X}.bin"
        write_codebook(path, aligned)
        aligned_paths.append(path)
    return raw_paths, deltas, aligned_paths


def print_segment_result(
    search_tool: Path,
    stage: int,
    key_words: Sequence[int],
    paths: Sequence[Path],
    delta_map: Dict[int, int],
    prefixes: Sequence[int],
    label: str,
) -> tuple[int, Dict[int, Path]]:
    shift, score = run_scan_shift(search_tool, stage, key_words, paths)
    best_k0, best_k0_score = run_scan_k0(search_tool, stage, shift, key_words[1], paths)
    best_k1, best_k1_score = run_scan_k1(search_tool, stage, shift, key_words[0], paths)
    print(f"[+] {label} bridge deltas: {[f'{delta_map[p]:04X}' for p in prefixes[1:]]}")
    print(f"[+] {label} common shift={shift:04X}  score={score}")
    print(f"[+] {label} row max: {best_k0:04X}  score={best_k0_score}")
    print(f"[+] {label} col max: {best_k1:04X}  score={best_k1_score}")
    return shift


def sample_pairs_from_codebook(path: Path, indices: Sequence[int]) -> List[tuple[int, int]]:
    book = read_codebook(path)
    inputs = sorted(book)
    return [(inputs[index], book[inputs[index]]) for index in indices]


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Demonstrate the exact recursive block-2 key-recovery peel against the real SEPAR DLL. "
            "Given K8 and K7, the script recovers exact stage bridges from two full-domain "
            "block-2 codebooks and peels inward through K6, K5, K4, K3, K2, and finally K1."
        )
    )
    parser.add_argument("--dll", default="SEPAR/SEPAR.dll")
    parser.add_argument("--iv", default="00000000000000000000000000000000")
    parser.add_argument("--prefixes", default="0,1")
    parser.add_argument("--k8", default="FC7D6371")
    parser.add_argument("--k7", default="8D1E9DF5")
    parser.add_argument("--k6", default="F44A233E")
    parser.add_argument("--k5", default="50C512DB")
    parser.add_argument("--k4", default="E95307FD")
    parser.add_argument("--k3", default="02DD3972")
    parser.add_argument("--k2", default="DA5D96D7")
    parser.add_argument("--k1", default="E8B9B733")
    parser.add_argument(
        "--delta-tool",
        default="key recovery/v45_delta_search.exe",
        help="Path to the exhaustive delta-search helper",
    )
    parser.add_argument(
        "--search-tool",
        default="key recovery/multi_dataset_peel_tool_omp.exe",
        help="Path to the multi-dataset peel helper",
    )
    parser.add_argument(
        "--work-dir",
        default="outer_half_recursive_break",
        help="Directory for generated .bin files. Relative paths are created under key recovery/data.",
    )
    args = parser.parse_args()

    iv_words = hex_words(args.iv, 8)
    prefixes = [int(part, 0) & MASK16 for part in args.prefixes.split(",") if part]
    if len(prefixes) < 2:
        raise SystemExit("at least two prefixes are required")

    k8_words = hex_words(args.k8, 2)
    k7_words = hex_words(args.k7, 2)
    k6_words = hex_words(args.k6, 2)
    k5_words = hex_words(args.k5, 2)
    k4_words = hex_words(args.k4, 2)
    k3_words = hex_words(args.k3, 2)
    k2_words = hex_words(args.k2, 2)
    k1_words = hex_words(args.k1, 2)

    oracle_fn = load_oracle(Path(args.dll))
    inv8 = inverse_stage_table(k8_words, 8)
    inv7 = inverse_stage_table(k7_words, 7)
    inv6 = inverse_stage_table(k6_words, 6)
    inv5 = inverse_stage_table(k5_words, 5)
    inv4 = inverse_stage_table(k4_words, 4)
    inv3 = inverse_stage_table(k3_words, 3)
    inv2 = inverse_stage_table(k2_words, 2)
    suffixes = list(range(65536))

    delta_tool = Path(args.delta_tool)
    search_tool = Path(args.search_tool)
    work_dir = resolve_data_path(args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    # Stage 8: build peeled block-2 codebooks and recover exact Delta v45(prefix).
    raw_stage8_paths: Dict[int, Path] = {}
    for prefix in prefixes:
        ct2 = dll_second_block_codebook(oracle_fn, prefix, iv_words, suffixes)
        peeled = {suffix: inv8[value] for suffix, value in ct2.items()}
        path = work_dir / f"stage8_raw_{prefix:04X}.bin"
        write_codebook(path, peeled)
        raw_stage8_paths[prefix] = path

    ref = prefixes[0]
    delta_v45 = {ref: 0}
    for prefix in prefixes[1:]:
        # The stage-8 delta search returns the opposite orientation of the alignment
        # used by the recursive peel, so negate it here.
        delta_v45[prefix] = (-run_delta_search(delta_tool, raw_stage8_paths[ref], raw_stage8_paths[prefix])) & MASK16

    aligned_stage8_paths: List[Path] = []
    for prefix in prefixes:
        aligned = align_codebook(read_codebook(raw_stage8_paths[prefix]), delta_v45[prefix])
        path = work_dir / f"stage8_aligned_{prefix:04X}.bin"
        write_codebook(path, aligned)
        aligned_stage8_paths.append(path)

    shift7, score7 = run_scan_shift(search_tool, 7, k7_words, aligned_stage8_paths)
    print(f"[+] stage7 common shift={shift7:04X}  score={score7}")

    current_paths = {prefix: work_dir / f"stage8_aligned_{prefix:04X}.bin" for prefix in prefixes}

    raw_stage6_paths, delta_stage7, aligned_stage6_paths = build_stage_paths(
        work_dir, "stage6", prefixes, current_paths, inv7, shift7, delta_tool
    )
    shift6 = print_segment_result(search_tool, 6, k6_words, aligned_stage6_paths, delta_stage7, prefixes, "K6")

    current_paths = {prefix: aligned_stage6_paths[index] for index, prefix in enumerate(prefixes)}
    raw_stage5_paths, delta_stage6, aligned_stage5_paths = build_stage_paths(
        work_dir, "stage5", prefixes, current_paths, inv6, shift6, delta_tool
    )
    shift5 = print_segment_result(search_tool, 5, k5_words, aligned_stage5_paths, delta_stage6, prefixes, "K5")

    current_paths = {prefix: aligned_stage5_paths[index] for index, prefix in enumerate(prefixes)}
    raw_stage4_paths, delta_stage5, aligned_stage4_paths = build_stage_paths(
        work_dir, "stage4", prefixes, current_paths, inv5, shift5, delta_tool
    )
    shift4 = print_segment_result(search_tool, 4, k4_words, aligned_stage4_paths, delta_stage5, prefixes, "K4")

    current_paths = {prefix: aligned_stage4_paths[index] for index, prefix in enumerate(prefixes)}
    raw_stage3_paths, delta_stage4, aligned_stage3_paths = build_stage_paths(
        work_dir, "stage3", prefixes, current_paths, inv4, shift4, delta_tool
    )
    shift3 = print_segment_result(search_tool, 3, k3_words, aligned_stage3_paths, delta_stage4, prefixes, "K3")

    current_paths = {prefix: aligned_stage3_paths[index] for index, prefix in enumerate(prefixes)}
    raw_stage2_paths, delta_stage3, aligned_stage2_paths = build_stage_paths(
        work_dir, "stage2", prefixes, current_paths, inv3, shift3, delta_tool
    )
    shift2 = print_segment_result(search_tool, 2, k2_words, aligned_stage2_paths, delta_stage3, prefixes, "K2")

    current_paths = {prefix: aligned_stage2_paths[index] for index, prefix in enumerate(prefixes)}
    raw_stage1_paths, delta_stage2, aligned_stage1_paths = build_stage_paths(
        work_dir, "stage1", prefixes, current_paths, inv2, shift2, delta_tool
    )
    print(f"[+] K1 bridge deltas: {[f'{delta_stage2[p]:04X}' for p in prefixes[1:]]}")

    solver_pairs = sample_pairs_from_codebook(
        aligned_stage1_paths[0],
        [0, 1, 2, 3, 4, 17, 257, 1024, 4096, 8192, 16384, 24576, 32768, 40960, 49152, 57344, 6553, 7777, 12345, 54321],
    )
    result, elapsed, recovered = solve_stage(1, solver_pairs, True, True, 600000)
    print(f"[+] K1 exact solver result: {result}  elapsed={elapsed:.3f}s")
    if recovered is not None:
        print(f"[+] K1 recovered: {recovered['key0']:04X}{recovered['key1']:04X}")
        print(f"[+] K1 input shift:  {recovered['input_shift']:04X}")
        print(f"[+] K1 output shift: {recovered['output_shift']:04X}")
    print(f"[+] wrote intermediate codebooks under {work_dir}")


if __name__ == "__main__":
    main()
