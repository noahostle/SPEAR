import argparse
import ctypes
import random
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
COMMON_DIR = ROOT.parent / "per_block_diff"
if str(COMMON_DIR) not in sys.path:
    sys.path.insert(0, str(COMMON_DIR))

from separ_analysis_common import resolve_separ_dll_path  # noqa: E402


DLL_PATH = resolve_separ_dll_path(__file__)


def _u16_array(values):
    arr_t = ctypes.c_uint16 * len(values)
    return arr_t(*values)


class SeparOracle:
    def __init__(self, dll_path: Path):
        self.lib = ctypes.CDLL(str(dll_path))

        self.enc = self.lib.separ_encrypt_words
        self.enc.argtypes = [
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint16),
        ]
        self.enc.restype = ctypes.c_int

        self.dec = self.lib.separ_decrypt_words
        self.dec.argtypes = self.enc.argtypes
        self.dec.restype = ctypes.c_int

    def encrypt_words(self, words, key_words, iv_words):
        n = len(words)
        pt = _u16_array(words)
        ct = (ctypes.c_uint16 * n)()
        key = _u16_array(key_words)
        iv = _u16_array(iv_words)
        rc = self.enc(pt, n, key, iv, ct)
        if rc != 0:
            raise RuntimeError(f"encryption failed with code {rc}")
        return list(ct)

    def decrypt_words(self, words, key_words, iv_words):
        n = len(words)
        ct = _u16_array(words)
        pt = (ctypes.c_uint16 * n)()
        key = _u16_array(key_words)
        iv = _u16_array(iv_words)
        rc = self.dec(ct, n, key, iv, pt)
        if rc != 0:
            raise RuntimeError(f"decryption failed with code {rc}")
        return list(pt)


def rand_words(rng: random.Random, n: int):
    return [rng.randrange(0x10000) for _ in range(n)]


def verify_sampled(oracle: SeparOracle, rng: random.Random, prefix_len: int, trials: int, samples: int):
    for trial in range(1, trials + 1):
        key = rand_words(rng, 16)
        iv = rand_words(rng, 8)
        prefix_pt = rand_words(rng, prefix_len)
        prefix_ct = oracle.encrypt_words(prefix_pt, key, iv)

        for _ in range(samples):
            x = rng.randrange(0x10000)
            y = oracle.encrypt_words(prefix_pt + [x], key, iv)[-1]
            x_back = oracle.decrypt_words(prefix_ct + [y], key, iv)[-1]
            if x_back != x:
                raise AssertionError(
                    f"sampled forward/inverse mismatch: x={x:04x}, y={y:04x}, recovered={x_back:04x}"
                )

            y2 = rng.randrange(0x10000)
            x2 = oracle.decrypt_words(prefix_ct + [y2], key, iv)[-1]
            y_back = oracle.encrypt_words(prefix_pt + [x2], key, iv)[-1]
            if y_back != y2:
                raise AssertionError(
                    f"sampled inverse/forward mismatch: y={y2:04x}, x={x2:04x}, recovered={y_back:04x}"
                )

        print(
            f"[sampled] trial {trial}/{trials} passed "
            f"(prefix_len={prefix_len}, samples={samples})"
        )


def verify_full_codebook(oracle: SeparOracle, rng: random.Random, prefix_len: int):
    key = rand_words(rng, 16)
    iv = rand_words(rng, 8)
    prefix_pt = rand_words(rng, prefix_len)
    prefix_ct = oracle.encrypt_words(prefix_pt, key, iv)

    forward = [0] * 0x10000
    inverse = [0] * 0x10000

    for x in range(0x10000):
        forward[x] = oracle.encrypt_words(prefix_pt + [x], key, iv)[-1]

    for y in range(0x10000):
        inverse[y] = oracle.decrypt_words(prefix_ct + [y], key, iv)[-1]

    for x in range(0x10000):
        y = forward[x]
        if inverse[y] != x:
            raise AssertionError(
                f"full-codebook mismatch at x={x:04x}: F(x)={y:04x}, G(F(x))={inverse[y]:04x}"
            )

    for y in range(0x10000):
        x = inverse[y]
        if forward[x] != y:
            raise AssertionError(
                f"full-codebook mismatch at y={y:04x}: G(y)={x:04x}, F(G(y))={forward[x]:04x}"
            )

    print("[full] exact matched-context inverse check passed for all 65536 values")
    print(f"[full] prefix plaintext: {[f'{w:04x}' for w in prefix_pt]}")
    print(f"[full] prefix ciphertext: {[f'{w:04x}' for w in prefix_ct]}")


def main():
    parser = argparse.ArgumentParser(
        description="Verify the matched-context forward/inverse oracle primitive for SEPAR.dll"
    )
    parser.add_argument("--prefix-len", type=int, default=1, help="plaintext prefix length in 16-bit words")
    parser.add_argument("--trials", type=int, default=8, help="number of sampled random contexts")
    parser.add_argument("--samples", type=int, default=128, help="number of sampled points per context")
    parser.add_argument("--seed", type=int, default=0x53455041, help="PRNG seed")
    parser.add_argument(
        "--full-codebook",
        action="store_true",
        help="also verify one exact 65536-point forward/inverse codebook pair",
    )
    args = parser.parse_args()

    oracle = SeparOracle(DLL_PATH)
    rng = random.Random(args.seed)

    verify_sampled(oracle, rng, args.prefix_len, args.trials, args.samples)
    if args.full_codebook:
        verify_full_codebook(oracle, rng, args.prefix_len)


if __name__ == "__main__":
    main()
