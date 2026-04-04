#!/usr/bin/env python3

import argparse
import ctypes
import os
import random
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
SEPAR_DIR = os.path.join(ROOT_DIR, "SEPAR")
DEFAULT_DLL = os.path.join(SEPAR_DIR, "SEPAR.dll")


S1 = [1, 15, 11, 2, 0, 3, 5, 8, 6, 9, 12, 7, 13, 10, 14, 4]
S2 = [6, 10, 15, 4, 14, 13, 9, 2, 1, 7, 12, 11, 0, 3, 5, 8]
S3 = [12, 2, 6, 1, 0, 3, 5, 8, 7, 9, 11, 14, 10, 13, 15, 4]
S4 = [13, 11, 2, 7, 0, 3, 5, 8, 6, 12, 15, 1, 10, 4, 9, 14]

IS1 = [4, 0, 3, 5, 15, 6, 8, 11, 7, 9, 13, 2, 10, 12, 14, 1]
IS2 = [12, 8, 7, 13, 3, 14, 0, 9, 15, 6, 1, 11, 10, 5, 4, 2]
IS3 = [4, 3, 1, 5, 15, 6, 2, 8, 7, 9, 12, 10, 0, 13, 11, 14]
IS4 = [4, 11, 2, 5, 13, 6, 8, 3, 7, 14, 12, 1, 9, 0, 15, 10]

DEFAULT_DIFFS = [0x0001, 0x0002, 0x0004, 0x0008, 0x000F, 0x0010]
DEFAULT_HI_VALUES = [0x00, 0x20, 0x40, 0x80, 0xA0, 0xFF]


def rotl16(x: int, y: int) -> int:
    y &= 15
    return ((x << y) | (x >> (16 - y))) & 0xFFFF


def rotr16(x: int, y: int) -> int:
    y &= 15
    return ((x >> y) | (x << (16 - y))) & 0xFFFF


def do_sbox(x: int) -> int:
    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF
    return (S1[a] << 12) | (S2[b] << 8) | (S3[c] << 4) | S4[d]


def do_isbox(x: int) -> int:
    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF
    return (IS1[a] << 12) | (IS2[b] << 8) | (IS3[c] << 4) | IS4[d]


def sep_rotl16(x: int) -> int:
    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF

    a ^= c
    b ^= d
    c ^= b
    d ^= a

    x = ((a << 12) | (b << 8) | (c << 4) | d) & 0xFFFF
    return (x ^ rotl16(x, 12) ^ rotl16(x, 8)) & 0xFFFF


def sep_inrotl16(x: int) -> int:
    y = rotr16(x, 12)
    z = rotr16(x, 8)
    x = (x ^ y ^ z) & 0xFFFF

    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF

    d ^= a
    c ^= b
    b ^= d
    a ^= c
    return ((a << 12) | (b << 8) | (c << 4) | d) & 0xFFFF


def derive_key23(k0: int, k1: int, n: int) -> Tuple[int, int]:
    key2 = rotl16(k0, 6)
    b = (key2 >> 6) & 0xF
    key2 |= S1[b] << 6
    key2 ^= (n + 2)
    key2 &= 0xFFFF

    key3 = rotl16(k1, 10)
    b = (key3 >> 6) & 0xF
    key3 |= S1[b] << 6
    key3 ^= (n + 3)
    key3 &= 0xFFFF

    return key2, key3


def enc_block(pt: int, key_pair: Tuple[int, int], n: int) -> int:
    k0, k1 = key_pair
    key2, key3 = derive_key23(k0, k1, n)

    t = pt ^ k0
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= k1
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= key2
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= key3
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= (k0 ^ k1)
    t = do_sbox(t)
    t ^= (key2 ^ key3)
    return t & 0xFFFF


def dec_block(ct: int, key_pair: Tuple[int, int], n: int) -> int:
    k0, k1 = key_pair
    key2, key3 = derive_key23(k0, k1, n)

    t = (ct ^ key2 ^ key3) & 0xFFFF
    t = do_isbox(t)
    t ^= (k0 ^ k1)
    t &= 0xFFFF

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= key3
    t &= 0xFFFF

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= key2
    t &= 0xFFFF

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= k1
    t &= 0xFFFF

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= k0
    return t & 0xFFFF


def parse_hex_word(token: str) -> int:
    token = token.strip().lower()
    if token.startswith("0x"):
        token = token[2:]
    if not token:
        raise ValueError("empty hex token")
    return int(token, 16) & 0xFFFF


def parse_word_list(text: str) -> List[int]:
    if not text:
        return []
    return [parse_hex_word(part) for part in text.split(",") if part.strip()]


def parse_key_pair(text: str) -> Tuple[int, int]:
    words = parse_word_list(text)
    if len(words) != 2:
        raise ValueError("expected exactly two 16-bit words")
    return words[0], words[1]


def parse_full_key_hex(text: str) -> List[int]:
    cleaned = text.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 64:
        raise ValueError("full key must contain exactly 64 hex characters")
    return [int(cleaned[i:i + 4], 16) for i in range(0, 64, 4)]


def parse_full_iv_hex(text: str) -> List[int]:
    cleaned = text.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 32:
        raise ValueError("IV must contain exactly 32 hex characters")
    return [int(cleaned[i:i + 4], 16) for i in range(0, 32, 4)]


def words_to_hex(words: Sequence[int]) -> str:
    return "".join(f"{word & 0xFFFF:04X}" for word in words)


class BlackBoxOracle:
    def __init__(self, dll_path: str, key_words: Optional[Sequence[int]] = None):
        if not os.path.exists(dll_path):
            raise FileNotFoundError(f"could not find DLL: {dll_path}")

        self.lib = ctypes.CDLL(os.path.abspath(dll_path))

        self.encrypt_words_fn = self.lib.separ_encrypt_words
        self.encrypt_words_fn.argtypes = [
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint16),
        ]
        self.encrypt_words_fn.restype = ctypes.c_int

        self.decrypt_words_fn = self.lib.separ_decrypt_words
        self.decrypt_words_fn.argtypes = self.encrypt_words_fn.argtypes
        self.decrypt_words_fn.restype = ctypes.c_int

        self.key_buf = None
        if key_words is not None:
            arr_t = ctypes.c_uint16 * len(key_words)
            self.key_buf = arr_t(*key_words)

    @staticmethod
    def _u16_array(values: Sequence[int]):
        arr_t = ctypes.c_uint16 * len(values)
        return arr_t(*values)

    def encrypt_words(self, words: Sequence[int], iv_words: Sequence[int]) -> List[int]:
        n = len(words)
        pt = self._u16_array(words)
        ct = (ctypes.c_uint16 * n)()
        iv = self._u16_array(iv_words)
        rc = self.encrypt_words_fn(pt, n, self.key_buf, iv, ct)
        if rc != 0:
            raise RuntimeError(f"separ_encrypt_words failed with code {rc}")
        return list(ct)

    def decrypt_words(self, words: Sequence[int], iv_words: Sequence[int]) -> List[int]:
        n = len(words)
        ct = self._u16_array(words)
        pt = (ctypes.c_uint16 * n)()
        iv = self._u16_array(iv_words)
        rc = self.decrypt_words_fn(ct, n, self.key_buf, iv, pt)
        if rc != 0:
            raise RuntimeError(f"separ_decrypt_words failed with code {rc}")
        return list(pt)


def build_forward_inverse_codebooks(
    oracle: BlackBoxOracle,
    prefix_words: Sequence[int],
    iv_words: Sequence[int],
    *,
    need_inverse: bool = True,
) -> Tuple[List[int], List[int], Optional[List[int]]]:
    prefix_words = list(prefix_words)
    prefix_ct = oracle.encrypt_words(prefix_words, iv_words)

    forward = [0] * 0x10000
    inverse = [0] * 0x10000 if need_inverse else None

    for x in range(0x10000):
        forward[x] = oracle.encrypt_words(prefix_words + [x], iv_words)[-1]

    if inverse is not None:
        for y in range(0x10000):
            inverse[y] = oracle.decrypt_words(prefix_ct + [y], iv_words)[-1]

    return prefix_ct, forward, inverse


def exact_additive_score(table: Sequence[int], diffs: Sequence[int]) -> int:
    total = 0
    for diff in diffs:
        counts: Dict[int, int] = {}
        for x in range(0x10000):
            out_diff = (table[(x + diff) & 0xFFFF] - table[x]) & 0xFFFF
            counts[out_diff] = counts.get(out_diff, 0) + 1
        total += max(counts.values())
    return total


def row_branch_score(table: Sequence[int], hi_values: Sequence[int]) -> float:
    total = 0
    for hi in hi_values:
        upper_values = set()
        base = (hi & 0xFF) << 8
        for lo in range(256):
            upper_values.add((table[base | lo] >> 8) & 0xFF)
        total += len(upper_values)
    return total / float(len(hi_values))


def recover_low_byte_from_table(table: Sequence[int], hi_values: Sequence[int]) -> Tuple[int, float]:
    best_lo = 0
    best_score = float("inf")
    for lo in range(256):
        shifted = [0] * 0x10000
        for i, value in enumerate(table):
            shifted[i] = (value - lo) & 0xFFFF
        score = row_branch_score(shifted, hi_values)
        if score < best_score:
            best_score = score
            best_lo = lo
    return best_lo, best_score


def score_k8_candidates(
    forward_table: Sequence[int],
    candidates: Sequence[Tuple[int, int]],
    diffs: Sequence[int],
) -> List[Tuple[int, Tuple[int, int]]]:
    ranked = []
    for pair in candidates:
        peeled = [dec_block(value, pair, 8) for value in forward_table]
        ranked.append((exact_additive_score(peeled, diffs), pair))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return ranked


def score_k1_candidates(
    inverse_table: Sequence[int],
    s1: int,
    candidates: Sequence[Tuple[int, int]],
    diffs: Sequence[int],
) -> List[Tuple[int, Tuple[int, int]]]:
    ranked = []
    for pair in candidates:
        peeled = [enc_block((value + s1) & 0xFFFF, pair, 1) for value in inverse_table]
        ranked.append((exact_additive_score(peeled, diffs), pair))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return ranked


def search_weak_iv(
    oracle: BlackBoxOracle,
    trials: int,
    seed: int,
    hi_values: Sequence[int],
) -> Tuple[List[int], float]:
    rng = random.Random(seed)
    best_iv: Optional[List[int]] = None
    best_score = float("inf")
    for trial in range(1, trials + 1):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        score = 0.0
        for hi in hi_values:
            upper_outputs = set()
            for lo in range(256):
                ct = oracle.encrypt_words([((hi & 0xFF) << 8) | lo], iv_words)[0]
                upper_outputs.add((ct >> 8) & 0xFF)
            score += float(len(upper_outputs))
        score /= float(len(hi_values))

        if score < best_score:
            best_score = score
            best_iv = iv_words
            print(
                f"[+] new best IV at trial {trial}/{trials}: "
                f"score={best_score:.2f} iv={words_to_hex(best_iv)}"
            )

    if best_iv is None:
        raise RuntimeError("weak-IV search did not produce a candidate")
    return best_iv, best_score


def search_weak_iv_inverse(
    oracle: BlackBoxOracle,
    trials: int,
    seed: int,
    hi_values: Sequence[int],
) -> Tuple[List[int], float]:
    rng = random.Random(seed)
    best_iv: Optional[List[int]] = None
    best_score = float("inf")
    for trial in range(1, trials + 1):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        score = 0.0
        for hi in hi_values:
            upper_outputs = set()
            for lo in range(256):
                pt = oracle.decrypt_words([((hi & 0xFF) << 8) | lo], iv_words)[0]
                upper_outputs.add((pt >> 8) & 0xFF)
            score += float(len(upper_outputs))
        score /= float(len(hi_values))

        if score < best_score:
            best_score = score
            best_iv = iv_words
            print(
                f"[+] new best inverse IV at trial {trial}/{trials}: "
                f"score={best_score:.2f} iv={words_to_hex(best_iv)}"
            )

    if best_iv is None:
        raise RuntimeError("inverse weak-IV search did not produce a candidate")
    return best_iv, best_score


def search_joint_weak_iv(
    oracle: BlackBoxOracle,
    trials: int,
    seed: int,
    hi_values: Sequence[int],
) -> Tuple[List[int], float, float, float]:
    rng = random.Random(seed)
    best_iv: Optional[List[int]] = None
    best_total = float("inf")
    best_forward = float("inf")
    best_inverse = float("inf")
    for trial in range(1, trials + 1):
        iv_words = [rng.randrange(0x10000) for _ in range(8)]
        forward_score = 0.0
        inverse_score = 0.0
        for hi in hi_values:
            upper_ct = set()
            upper_pt = set()
            for lo in range(256):
                word = ((hi & 0xFF) << 8) | lo
                ct = oracle.encrypt_words([word], iv_words)[0]
                pt = oracle.decrypt_words([word], iv_words)[0]
                upper_ct.add((ct >> 8) & 0xFF)
                upper_pt.add((pt >> 8) & 0xFF)
            forward_score += float(len(upper_ct))
            inverse_score += float(len(upper_pt))
        forward_score /= float(len(hi_values))
        inverse_score /= float(len(hi_values))
        total = forward_score + inverse_score

        if total < best_total:
            best_total = total
            best_forward = forward_score
            best_inverse = inverse_score
            best_iv = iv_words
            print(
                f"[+] new best joint IV at trial {trial}/{trials}: "
                f"total={best_total:.2f} enc={best_forward:.2f} dec={best_inverse:.2f} "
                f"iv={words_to_hex(best_iv)}"
            )

    if best_iv is None:
        raise RuntimeError("joint weak-IV search did not produce a candidate")
    return best_iv, best_total, best_forward, best_inverse


def build_middle_table(
    forward_table: Sequence[int],
    k1: Tuple[int, int],
    s1: int,
    k8: Tuple[int, int],
    s8: int,
) -> List[int]:
    middle = [0] * 0x10000
    for x in range(0x10000):
        u = enc_block((x + s1) & 0xFFFF, k1, 1)
        v = (dec_block(forward_table[x], k8, 8) - s8) & 0xFFFF
        middle[u] = v
    return middle


def build_r6_table(
    middle_table: Sequence[int],
    k7: Tuple[int, int],
    s7: int,
) -> List[int]:
    return [((dec_block(value, k7, 7) - s7) & 0xFFFF) for value in middle_table]


def parse_hi_values(text: str) -> List[int]:
    return [parse_hex_word(part) & 0xFF for part in text.split(",") if part.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hummingbird-style SEPAR stage-peel tooling: weak-IV search, K8 scoring, and reduced-cascade helpers."
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=[
            "weak-iv",
            "weak-iv-inverse",
            "weak-iv-both",
            "score-k8",
            "score-k1",
            "middle-demo",
            "score-k7",
            "k6-demo",
            "score-k6",
        ],
    )
    parser.add_argument("--dll", default=DEFAULT_DLL, help=f"path to SEPAR.dll (default: {DEFAULT_DLL})")
    parser.add_argument(
        "--key",
        help="optional 64-hex full key; omit to attack the DLL's built-in key as a black-box oracle",
    )
    parser.add_argument("--iv", help="32-hex IV")
    parser.add_argument("--prefix", default="", help="comma-separated plaintext prefix words in hex")
    parser.add_argument("--diffs", default=",".join(f"{d:04x}" for d in DEFAULT_DIFFS))
    parser.add_argument("--hi-values", default=",".join(f"{v:02x}" for v in DEFAULT_HI_VALUES))
    parser.add_argument("--trials", type=int, default=40, help="weak-IV search trials")
    parser.add_argument("--seed", type=int, default=0x53455041, help="PRNG seed")
    parser.add_argument("--candidate", action="append", default=[], help="candidate key pair as k0,k1 in hex")
    parser.add_argument("--random-candidates", type=int, default=12, help="number of random candidate pairs to add")
    parser.add_argument("--include-correct", action="store_true", help="include the true K8 when --key is supplied")
    parser.add_argument("--k1", help="known or guessed K1 as k0,k1 in hex for middle-demo")
    parser.add_argument("--k7", help="known or guessed K7 as k0,k1 in hex for reduced-cascade demos")
    parser.add_argument("--k8", help="known or guessed K8 as k0,k1 in hex for middle-demo")
    parser.add_argument("--s1", help="state_1 guess as 16-bit hex for middle-demo")
    parser.add_argument("--s7", help="state_7 guess as 16-bit hex for reduced-cascade demos")
    parser.add_argument("--s8", help="state_8 guess as 16-bit hex for middle-demo")
    parser.add_argument("--s8-low", help="state_8 low-byte guess as 16-bit/8-bit hex for middle-demo")
    args = parser.parse_args()

    key_words = parse_full_key_hex(args.key) if args.key else None
    oracle = BlackBoxOracle(args.dll, key_words=key_words)
    hi_values = parse_hi_values(args.hi_values)
    diffs = parse_word_list(args.diffs)

    if args.mode == "weak-iv":
        best_iv, best_score = search_weak_iv(oracle, args.trials, args.seed, hi_values)
        print()
        print("Best IV")
        print(f"  iv    = {words_to_hex(best_iv)}")
        print(f"  score = {best_score:.2f}")
        return

    if args.mode == "weak-iv-inverse":
        best_iv, best_score = search_weak_iv_inverse(oracle, args.trials, args.seed, hi_values)
        print()
        print("Best Inverse IV")
        print(f"  iv    = {words_to_hex(best_iv)}")
        print(f"  score = {best_score:.2f}")
        return

    if args.mode == "weak-iv-both":
        best_iv, best_total, best_forward, best_inverse = search_joint_weak_iv(
            oracle, args.trials, args.seed, hi_values
        )
        print()
        print("Best Joint IV")
        print(f"  iv         = {words_to_hex(best_iv)}")
        print(f"  total      = {best_total:.2f}")
        print(f"  enc_score  = {best_forward:.2f}")
        print(f"  dec_score  = {best_inverse:.2f}")
        return

    if args.iv is None:
        raise SystemExit("--iv is required for this mode")

    iv_words = parse_full_iv_hex(args.iv)
    prefix_words = parse_word_list(args.prefix)

    if args.mode == "score-k8":
        _, forward_table, _ = build_forward_inverse_codebooks(oracle, prefix_words, iv_words, need_inverse=False)

        candidates: List[Tuple[int, int]] = []
        seen = set()

        def add_candidate(pair: Tuple[int, int]) -> None:
            if pair not in seen:
                seen.add(pair)
                candidates.append(pair)

        for candidate_text in args.candidate:
            add_candidate(parse_key_pair(candidate_text))

        if key_words is not None and args.include_correct:
            add_candidate((key_words[14], key_words[15]))

        rng = random.Random(args.seed)
        target_count = len(candidates) + args.random_candidates
        while len(candidates) < target_count:
            add_candidate((rng.randrange(0x10000), rng.randrange(0x10000)))

        ranked = score_k8_candidates(forward_table, candidates, diffs)
        print("K8 candidate ranking")
        print(f"  iv      = {words_to_hex(iv_words)}")
        print(f"  prefix  = {[f'{word:04X}' for word in prefix_words]}")
        print(f"  diffs   = {[f'{diff:04X}' for diff in diffs]}")
        print()
        for rank, (score, pair) in enumerate(ranked, start=1):
            marker = ""
            if key_words is not None and pair == (key_words[14], key_words[15]):
                marker = "  <-- true K8"
            print(f"#{rank}: K8=({pair[0]:04X}, {pair[1]:04X}) score={score}{marker}")

        if ranked:
            best_pair = ranked[0][1]
            peeled = [dec_block(value, best_pair, 8) for value in forward_table]
            s8_low, branch_score = recover_low_byte_from_table(peeled, hi_values)
            print()
            print("Recovered low byte for the peeled outer translation")
            print(f"  candidate K8 = ({best_pair[0]:04X}, {best_pair[1]:04X})")
            print(f"  s8_low       = {s8_low:02X}")
            print(f"  row_score    = {branch_score:.2f}")
        return

    if args.mode == "score-k1":
        if args.s1 is None:
            raise SystemExit("--s1 is required for score-k1")

        _, _, inverse_table = build_forward_inverse_codebooks(oracle, prefix_words, iv_words, need_inverse=True)
        if inverse_table is None:
            raise RuntimeError("inverse table was not built")

        s1 = parse_hex_word(args.s1)

        candidates: List[Tuple[int, int]] = []
        seen = set()

        def add_candidate(pair: Tuple[int, int]) -> None:
            if pair not in seen:
                seen.add(pair)
                candidates.append(pair)

        for candidate_text in args.candidate:
            add_candidate(parse_key_pair(candidate_text))

        if key_words is not None and args.include_correct:
            add_candidate((key_words[0], key_words[1]))

        rng = random.Random(args.seed)
        target_count = len(candidates) + args.random_candidates
        while len(candidates) < target_count:
            add_candidate((rng.randrange(0x10000), rng.randrange(0x10000)))

        ranked = score_k1_candidates(inverse_table, s1, candidates, diffs)
        print("K1 candidate ranking")
        print(f"  iv      = {words_to_hex(iv_words)}")
        print(f"  prefix  = {[f'{word:04X}' for word in prefix_words]}")
        print(f"  s1      = {s1:04X}")
        print(f"  diffs   = {[f'{diff:04X}' for diff in diffs]}")
        print()
        for rank, (score, pair) in enumerate(ranked, start=1):
            marker = ""
            if key_words is not None and pair == (key_words[0], key_words[1]):
                marker = "  <-- true K1"
            print(f"#{rank}: K1=({pair[0]:04X}, {pair[1]:04X}) score={score}{marker}")
        return

    if args.mode in ("middle-demo", "score-k7"):
        if args.k1 is None or args.k8 is None or args.s1 is None:
            raise SystemExit("--k1, --k8, and --s1 are required for this mode")
        if args.s8 is None and args.s8_low is None:
            raise SystemExit("this mode requires either --s8 or --s8-low")

        k1 = parse_key_pair(args.k1)
        k8 = parse_key_pair(args.k8)
        s1 = parse_hex_word(args.s1)
        if args.s8 is not None:
            s8 = parse_hex_word(args.s8)
        else:
            s8 = parse_hex_word(args.s8_low)

        _, forward_table, _ = build_forward_inverse_codebooks(oracle, prefix_words, iv_words, need_inverse=False)
        middle = build_middle_table(forward_table, k1, s1, k8, s8)

        candidates: List[Tuple[int, int]] = []
        seen = set()

        def add_candidate(pair: Tuple[int, int]) -> None:
            if pair not in seen:
                seen.add(pair)
                candidates.append(pair)

        for candidate_text in args.candidate:
            add_candidate(parse_key_pair(candidate_text))

        rng = random.Random(args.seed)
        target_count = len(candidates) + args.random_candidates
        while len(candidates) < target_count:
            add_candidate((rng.randrange(0x10000), rng.randrange(0x10000)))

        ranked = []
        for pair in candidates:
            peeled = [dec_block(value, pair, 7) for value in middle]
            ranked.append((exact_additive_score(peeled, diffs), pair))
        ranked.sort(key=lambda item: (-item[0], item[1]))

        print("Middle-permutation K7 demo")
        print(f"  iv      = {words_to_hex(iv_words)}")
        print(f"  prefix  = {[f'{word:04X}' for word in prefix_words]}")
        print(f"  K1      = ({k1[0]:04X}, {k1[1]:04X})")
        print(f"  K8      = ({k8[0]:04X}, {k8[1]:04X})")
        print(f"  s1      = {s1:04X}")
        print(f"  s8      = {s8:04X}")
        print(f"  row(M)  = {row_branch_score(middle, hi_values):.2f}")
        print()
        for rank, (score, pair) in enumerate(ranked, start=1):
            print(f"#{rank}: K7=({pair[0]:04X}, {pair[1]:04X}) score={score}")
        return

    if args.mode in ("k6-demo", "score-k6"):
        if args.k1 is None or args.k7 is None or args.k8 is None:
            raise SystemExit("--k1, --k7, and --k8 are required for this mode")
        if args.s1 is None or args.s7 is None or args.s8 is None:
            raise SystemExit("--s1, --s7, and --s8 are required for this mode")

        k1 = parse_key_pair(args.k1)
        k7 = parse_key_pair(args.k7)
        k8 = parse_key_pair(args.k8)
        s1 = parse_hex_word(args.s1)
        s7 = parse_hex_word(args.s7)
        s8 = parse_hex_word(args.s8)

        _, forward_table, _ = build_forward_inverse_codebooks(oracle, prefix_words, iv_words, need_inverse=False)
        middle = build_middle_table(forward_table, k1, s1, k8, s8)
        r6 = build_r6_table(middle, k7, s7)

        candidates: List[Tuple[int, int]] = []
        seen = set()

        def add_candidate(pair: Tuple[int, int]) -> None:
            if pair not in seen:
                seen.add(pair)
                candidates.append(pair)

        for candidate_text in args.candidate:
            add_candidate(parse_key_pair(candidate_text))

        rng = random.Random(args.seed)
        target_count = len(candidates) + args.random_candidates
        while len(candidates) < target_count:
            add_candidate((rng.randrange(0x10000), rng.randrange(0x10000)))

        ranked = []
        for pair in candidates:
            peeled = [dec_block(value, pair, 6) for value in r6]
            ranked.append((exact_additive_score(peeled, diffs), pair))
        ranked.sort(key=lambda item: (-item[0], item[1]))

        print("Reduced-Cascade K6 demo")
        print(f"  iv      = {words_to_hex(iv_words)}")
        print(f"  prefix  = {[f'{word:04X}' for word in prefix_words]}")
        print(f"  K1      = ({k1[0]:04X}, {k1[1]:04X})")
        print(f"  K7      = ({k7[0]:04X}, {k7[1]:04X})")
        print(f"  K8      = ({k8[0]:04X}, {k8[1]:04X})")
        print(f"  s1      = {s1:04X}")
        print(f"  s7      = {s7:04X}")
        print(f"  s8      = {s8:04X}")
        print(f"  row(R6) = {row_branch_score(r6, hi_values):.2f}")
        print()
        for rank, (score, pair) in enumerate(ranked, start=1):
            print(f"#{rank}: K6=({pair[0]:04X}, {pair[1]:04X}) score={score}")
        return


if __name__ == "__main__":
    main()
