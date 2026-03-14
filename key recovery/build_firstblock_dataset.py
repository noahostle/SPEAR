from __future__ import annotations

import argparse
import ctypes
import struct
from pathlib import Path
from typing import List

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


def parse_hex_words(text: str, expected_words: int) -> List[int]:
    cleaned = text.strip().removeprefix("0x").removeprefix("0X")
    if len(cleaned) != expected_words * 4:
        raise SystemExit(f"expected exactly {expected_words * 4} hex chars")
    return [int(cleaned[index : index + 4], 16) for index in range(0, len(cleaned), 4)]


def resolve_dataset_path(path_text: str) -> Path:
    path = Path(path_text)
    if not path.is_absolute():
        path = DATA_DIR / path
    return path


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build a proper first-block K8 attack dataset from the real SEPAR oracle. "
            "Each plaintext is queried as a separate one-word message under the same IV."
        )
    )
    parser.add_argument("--dll", default="SEPAR/SEPAR.dll")
    parser.add_argument("--sample-size", type=int, default=1024, help="Chosen plaintexts are 0..sample-size-1")
    parser.add_argument("--alphas", default="1,2,3,4,5,6,7,8")
    parser.add_argument("--iv", required=True, help="128-bit IV as 32 hex chars")
    parser.add_argument(
        "--out",
        required=True,
        help="Output dataset path. Relative paths are written under key recovery/data.",
    )
    args = parser.parse_args()

    iv_words = parse_hex_words(args.iv, 8)
    alphas = [int(part, 0) & 0xFFFF for part in args.alphas.split(",") if part]
    need = sorted(set(range(args.sample_size)).union(*[{(x + alpha) & 0xFFFF for x in range(args.sample_size)} for alpha in alphas]))

    oracle_fn = load_oracle(Path(args.dll))
    pt_buf = (ctypes.c_uint16 * 1)()
    ct_buf = (ctypes.c_uint16 * 1)()
    iv_buf = (ctypes.c_uint16 * 8)(*iv_words)
    outputs: List[int] = []

    for pt in need:
        pt_buf[0] = pt
        rc = oracle_fn(pt_buf, 1, None, iv_buf, ct_buf)
        if rc != 0:
            raise RuntimeError(f"oracle returned error code {rc}")
        outputs.append(ct_buf[0])

    out_path = resolve_dataset_path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as handle:
        handle.write(struct.pack("<I", len(need)))
        handle.write(struct.pack(f"<{len(need)}H", *need))
        handle.write(struct.pack(f"<{len(need)}H", *outputs))

    print(f"[+] wrote {out_path} with {len(need)} independent first-block samples")
    print(f"[+] iv={''.join(f'{word:04X}' for word in iv_words)}")


if __name__ == "__main__":
    main()
