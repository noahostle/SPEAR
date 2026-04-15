#!/usr/bin/env python3

import argparse
import ctypes
import os
import random
import time
from typing import Dict, List, Optional, Sequence, Tuple

CHUNK_HEX_CHARS = 4
KEY_WORDS = 16
IV_WORDS = 8
DEFAULT_STAGES = [16, 32, 64, 128, 256]


def _default_lib_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../", "SEPAR", "SEPAR.dll")


def _normalize_hex_words(hex_string: str, *, expected_words: Optional[int] = None, field_name: str = "hex") -> str:
    hex_string = hex_string.strip()
    if hex_string.startswith(("0x", "0X")):
        hex_string = hex_string[2:]

    if len(hex_string) == 0 or (len(hex_string) % CHUNK_HEX_CHARS) != 0:
        raise ValueError(
            f"{field_name} length must be a positive multiple of {CHUNK_HEX_CHARS} hex chars (16-bit chunks)."
        )

    try:
        int(hex_string, 16)
    except ValueError as e:
        raise ValueError(f"{field_name} must be valid hex.") from e

    if expected_words is not None and (len(hex_string) // CHUNK_HEX_CHARS) != expected_words:
        raise ValueError(
            f"{field_name} must contain exactly {expected_words * CHUNK_HEX_CHARS} hex chars "
            f"({expected_words} x 16-bit words)."
        )

    return hex_string.upper()


def _hex_to_words(hex_string: str, *, expected_words: Optional[int] = None, field_name: str = "hex") -> List[int]:
    normalized = _normalize_hex_words(hex_string, expected_words=expected_words, field_name=field_name)
    return [int(normalized[i : i + CHUNK_HEX_CHARS], 16) for i in range(0, len(normalized), CHUNK_HEX_CHARS)]


def _words_to_hex(words: Sequence[int]) -> str:
    return "".join(f"{word & 0xFFFF:04X}" for word in words)


def _parse_stage_list(stage_string: str) -> List[int]:
    values = []
    for part in stage_string.split(","):
        part = part.strip()
        if not part:
            continue
        value = int(part, 10)
        if value < 1 or value > 256:
            raise ValueError("Stage values must be between 1 and 256.")
        values.append(value)
    if not values:
        raise ValueError("At least one stage value is required.")
    if values[-1] != 256:
        values.append(256)
    values = sorted(set(values))
    return values


def _parse_hi_values(hi_string: str) -> List[int]:
    values = []
    for part in hi_string.split(","):
        part = part.strip()
        if not part:
            continue
        values.append(int(part, 16) & 0xFF)
    if not values:
        raise ValueError("At least one score hi value is required.")
    return values


def _try_decode_words_as_text(words: Sequence[int]) -> Optional[str]:
    try:
        raw = bytes.fromhex(_words_to_hex(words))
        raw = raw.rstrip(b"\x00")
        return raw.decode("utf-8")
    except Exception:
        return None


class SeparOracle:
    """
    Local wrapper around the SEPAR DLL buffer APIs.
    `query_count` is counted in message-oracle calls, not per encrypted word.
    """

    def __init__(self, lib_path: Optional[str] = None, key_hex: Optional[str] = None):
        if lib_path is None:
            lib_path = _default_lib_path()
        if not os.path.exists(lib_path):
            raise FileNotFoundError(f"Shared library not found: {lib_path}")

        self._lib = ctypes.CDLL(os.path.abspath(lib_path))
        self._encrypt_words = self._bind_transform("separ_encrypt_words")
        self._decrypt_words = self._bind_transform("separ_decrypt_words")

        self._key_words = self._make_fixed_word_buffer(key_hex, KEY_WORDS, "key") if key_hex else None
        self.query_count = 0

    def _bind_transform(self, export_name: str):
        try:
            transform = getattr(self._lib, export_name)
        except AttributeError as e:
            raise RuntimeError(f"Required DLL export not found: {export_name}") from e

        transform.argtypes = (
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint16),
        )
        transform.restype = ctypes.c_int
        return transform

    @staticmethod
    def _make_fixed_word_buffer(hex_string: str, expected_words: int, field_name: str):
        words = _hex_to_words(hex_string, expected_words=expected_words, field_name=field_name)
        return (ctypes.c_uint16 * expected_words)(*words)

    def _run_transform(
        self,
        transform,
        input_words: Sequence[int],
        iv_words: Sequence[int],
        *,
        operation_name: str,
    ) -> List[int]:
        word_count = len(input_words)
        if len(iv_words) != IV_WORDS:
            raise ValueError(f"IV must contain exactly {IV_WORDS} 16-bit words.")

        in_buf = (ctypes.c_uint16 * word_count)(*input_words)
        out_buf = (ctypes.c_uint16 * word_count)()
        iv_buf = (ctypes.c_uint16 * IV_WORDS)(*iv_words)

        rc = transform(in_buf, word_count, self._key_words, iv_buf, out_buf)
        if rc != 0:
            raise RuntimeError(f"{operation_name} failed with status {rc}")

        return list(out_buf)

    def encrypt_words(self, plaintext_words: Sequence[int], iv_words: Sequence[int]) -> List[int]:
        ciphertext_words = self._run_transform(
            self._encrypt_words,
            plaintext_words,
            iv_words,
            operation_name="separ_encrypt_words",
        )

        self.query_count += 1
        return ciphertext_words

    def decrypt_words(self, ciphertext_words: Sequence[int], iv_words: Sequence[int]) -> List[int]:
        return self._run_transform(
            self._decrypt_words,
            ciphertext_words,
            iv_words,
            operation_name="separ_decrypt_words",
        )

    def encrypt_hex(self, plaintext_hex: str, iv_hex: str) -> str:
        pt_words = _hex_to_words(plaintext_hex, field_name="plaintext")
        iv_words = _hex_to_words(iv_hex, expected_words=IV_WORDS, field_name="iv")
        return _words_to_hex(self.encrypt_words(pt_words, iv_words))

    def decrypt_hex(self, ciphertext_hex: str, iv_hex: str) -> str:
        ct_words = _hex_to_words(ciphertext_hex, field_name="ciphertext")
        iv_words = _hex_to_words(iv_hex, expected_words=IV_WORDS, field_name="iv")
        return _words_to_hex(self.decrypt_words(ct_words, iv_words))


def score_iv(oracle: SeparOracle, iv_words: Sequence[int], hi_values: Sequence[int]) -> float:
    total = 0.0
    for hi in hi_values:
        upper_outputs = set()
        for lo in range(256):
            word = ((hi & 0xFF) << 8) | lo
            upper_outputs.add((oracle.encrypt_words([word], iv_words)[0] >> 8) & 0xFF)
        total += float(len(upper_outputs))
    return total / float(len(hi_values))


def search_weak_iv(
    oracle: SeparOracle,
    trials: int,
    seed: int,
    hi_values: Sequence[int],
    progress_every: int,
) -> Tuple[List[int], float]:
    rng = random.Random(seed)
    best_iv: Optional[List[int]] = None
    best_score = float("inf")
    started = time.perf_counter()

    for trial in range(1, trials + 1):
        iv_words = [rng.randrange(0x10000) for _ in range(IV_WORDS)]
        score = score_iv(oracle, iv_words, hi_values)

        if score < best_score:
            best_iv = iv_words[:]
            best_score = score
            print(
                f"[+] New best IV at trial {trial}/{trials}: "
                f"score={best_score:.2f} iv={_words_to_hex(best_iv)}"
            )

        if progress_every > 0 and (trial % progress_every) == 0:
            elapsed = time.perf_counter() - started
            print(
                f"[#] search progress {trial}/{trials} | best_score={best_score:.2f} "
                f"| oracle_queries={oracle.query_count} | elapsed={elapsed:.2f}s"
            )

    if best_iv is None:
        raise RuntimeError("IV search failed to produce any candidate.")

    return best_iv, best_score


class PositionRecoverer:
    """
    Exact adaptive recovery for one ciphertext word under a fixed prefix and chosen IV.

    The attack uses a cheap upper-byte sampling phase to narrow candidate upper plaintext
    bytes, then fully expands only those candidate upper-byte rows. If narrowing ever
    misses the true candidate, the stage list is extended until it reaches 256 low-byte
    probes, at which point success is guaranteed because the full fixed-state permutation
    row set has been enumerated.
    """

    def __init__(
        self,
        oracle: SeparOracle,
        iv_words: Sequence[int],
        prefix_words: Sequence[int],
        probe_order: Sequence[int],
    ):
        self.oracle = oracle
        self.iv_words = list(iv_words)
        self.prefix_words = list(prefix_words)
        self.probe_order = list(probe_order)
        self._word_cache: Dict[int, int] = {}
        self._sampled_upper: List[set[int]] = [set() for _ in range(256)]
        self._full_rows: Dict[int, List[int]] = {}
        self._sample_stop = 0

    def _query_candidate(self, candidate_word: int) -> int:
        candidate_word &= 0xFFFF
        cached = self._word_cache.get(candidate_word)
        if cached is not None:
            return cached

        ct_words = self.oracle.encrypt_words(self.prefix_words + [candidate_word], self.iv_words)
        ct_word = ct_words[-1]
        self._word_cache[candidate_word] = ct_word
        return ct_word

    def extend_sample_stage(self, new_stop: int) -> None:
        if new_stop <= self._sample_stop:
            return

        upper_limit = min(new_stop, 256)
        for hi in range(256):
            base = hi << 8
            row_upper = self._sampled_upper[hi]
            for idx in range(self._sample_stop, upper_limit):
                lo = self.probe_order[idx]
                ct_word = self._query_candidate(base | lo)
                row_upper.add((ct_word >> 8) & 0xFF)

        self._sample_stop = upper_limit

    def get_full_row(self, hi: int) -> List[int]:
        hi &= 0xFF
        row = self._full_rows.get(hi)
        if row is not None:
            return row

        row = [0] * 256
        base = hi << 8
        for lo in range(256):
            row[lo] = self._query_candidate(base | lo)

        self._full_rows[hi] = row
        return row

    def recover_word(self, target_ct_word: int, stages: Sequence[int]) -> Tuple[int, Dict[str, int]]:
        target_ct_word &= 0xFFFF
        target_upper = (target_ct_word >> 8) & 0xFF
        best_stage_candidate_count = 0

        for stage in stages:
            self.extend_sample_stage(stage)

            candidates = [hi for hi in range(256) if target_upper in self._sampled_upper[hi]]
            best_stage_candidate_count = len(candidates)
            candidates.sort(key=lambda hi: (len(self._sampled_upper[hi]), hi))

            for hi in candidates:
                row = self.get_full_row(hi)
                for lo, ct_word in enumerate(row):
                    if ct_word == target_ct_word:
                        recovered = (hi << 8) | lo
                        stats = {
                            "stage": self._sample_stop,
                            "candidate_upper_count": len(candidates),
                            "cached_words": len(self._word_cache),
                            "expanded_full_rows": len(self._full_rows),
                        }
                        return recovered, stats

        raise RuntimeError("Adaptive recovery unexpectedly failed after full stage expansion.")


def recover_message(
    oracle: SeparOracle,
    ciphertext_words: Sequence[int],
    iv_words: Sequence[int],
    stages: Sequence[int],
    seed: int,
) -> Tuple[List[int], List[Dict[str, int]]]:
    rng = random.Random(seed)
    probe_order = list(range(256))
    rng.shuffle(probe_order)

    recovered: List[int] = []
    per_word_stats: List[Dict[str, int]] = []

    for pos, ct_word in enumerate(ciphertext_words):
        start_queries = oracle.query_count
        recoverer = PositionRecoverer(oracle, iv_words, recovered, probe_order)
        pt_word, stats = recoverer.recover_word(ct_word, stages)
        stats["position"] = pos
        stats["oracle_queries"] = oracle.query_count - start_queries
        recovered.append(pt_word)
        per_word_stats.append(stats)

        print(
            f"[+] Recovered word {pos}: {pt_word:04X} "
            f"| stage={stats['stage']} "
            f"| upper_candidates={stats['candidate_upper_count']} "
            f"| queries={stats['oracle_queries']}"
        )

    return recovered, per_word_stats


def run_search_iv(args: argparse.Namespace) -> None:
    oracle = SeparOracle(args.lib, key_hex=args.key)
    hi_values = _parse_hi_values(args.score_his)
    best_iv, best_score = search_weak_iv(
        oracle=oracle,
        trials=args.search_trials,
        seed=args.seed,
        hi_values=hi_values,
        progress_every=args.progress_every,
    )
    print(f"[+] Best IV: {_words_to_hex(best_iv)}")
    print(f"[+] Best score: {best_score:.2f}")
    print(f"[+] Oracle queries used: {oracle.query_count}")


def run_recover(args: argparse.Namespace) -> None:
    if not args.ciphertext:
        raise SystemExit("--ciphertext is required for recover mode.")
    if not args.iv:
        raise SystemExit("--iv is required for recover mode.")

    oracle = SeparOracle(args.lib, key_hex=args.key)
    iv_words = _hex_to_words(args.iv, expected_words=IV_WORDS, field_name="iv")
    ciphertext_words = _hex_to_words(args.ciphertext, field_name="ciphertext")
    stages = _parse_stage_list(args.stages)

    print(f"[#] Recovering {len(ciphertext_words)} ciphertext words under IV {_words_to_hex(iv_words)}")
    recovered_words, per_word_stats = recover_message(
        oracle=oracle,
        ciphertext_words=ciphertext_words,
        iv_words=iv_words,
        stages=stages,
        seed=args.seed,
    )

    recovered_hex = _words_to_hex(recovered_words)
    print(f"[+] Recovered plaintext (hex): {recovered_hex}")
    dll_plaintext_words = oracle.decrypt_words(ciphertext_words, iv_words)
    if dll_plaintext_words != recovered_words:
        raise SystemExit(
            "[!] Attack output does not match separ_decrypt_words for the same ciphertext/key/IV."
        )
    print("[+] Verified recovered plaintext against separ_decrypt_words.")
    decoded = _try_decode_words_as_text(recovered_words)
    if decoded is not None:
        print(f"[+] Recovered plaintext (text): {decoded}")
    print(f"[+] Total oracle queries: {oracle.query_count}")

    if args.verbose_stats:
        for stats in per_word_stats:
            print(
                f"    pos={stats['position']} stage={stats['stage']} "
                f"upper_candidates={stats['candidate_upper_count']} "
                f"expanded_full_rows={stats['expanded_full_rows']} "
                f"cached_words={stats['cached_words']} "
                f"queries={stats['oracle_queries']}"
            )


def run_demo(args: argparse.Namespace) -> None:
    oracle = SeparOracle(args.lib, key_hex=args.key)
    hi_values = _parse_hi_values(args.score_his)
    stages = _parse_stage_list(args.stages)

    if args.iv:
        iv_words = _hex_to_words(args.iv, expected_words=IV_WORDS, field_name="iv")
        print(f"[#] Using caller-provided IV: {_words_to_hex(iv_words)}")
        best_score = score_iv(oracle, iv_words, hi_values)
        print(f"[+] Provided IV score: {best_score:.2f}")
    else:
        iv_words, best_score = search_weak_iv(
            oracle=oracle,
            trials=args.search_trials,
            seed=args.seed,
            hi_values=hi_values,
            progress_every=args.progress_every,
        )
        print(f"[+] Demo IV: {_words_to_hex(iv_words)}")
        print(f"[+] Demo IV score: {best_score:.2f}")

    if args.plaintext_hex:
        plaintext_words = _hex_to_words(args.plaintext_hex, field_name="plaintext")
    else:
        rng = random.Random(args.seed ^ 0xA5A5A5A5)
        plaintext_words = [rng.randrange(0x10000) for _ in range(args.demo_words)]

    ciphertext_words = oracle.encrypt_words(plaintext_words, iv_words)
    print(f"[+] Demo plaintext (hex): {_words_to_hex(plaintext_words)}")
    print(f"[+] Demo ciphertext (hex): {_words_to_hex(ciphertext_words)}")

    pre_attack_queries = oracle.query_count
    recovered_words, _ = recover_message(
        oracle=oracle,
        ciphertext_words=ciphertext_words,
        iv_words=iv_words,
        stages=stages,
        seed=args.seed,
    )
    attack_queries = oracle.query_count - pre_attack_queries

    recovered_hex = _words_to_hex(recovered_words)
    print(f"[+] Demo recovered (hex): {recovered_hex}")
    print(f"[+] Demo attack queries: {attack_queries}")

    if recovered_words != plaintext_words:
        raise SystemExit("[!] Demo recovery failed.")

    dll_recovered_words = oracle.decrypt_words(ciphertext_words, iv_words)
    if dll_recovered_words != plaintext_words:
        raise SystemExit("[!] separ_decrypt_words did not reproduce the demo plaintext.")
    print("[+] Verified demo ciphertext against separ_decrypt_words.")

    decoded = _try_decode_words_as_text(recovered_words)
    if decoded is not None:
        print(f"[+] Demo recovered (text): {decoded}")
    print("[+] Demo recovery verified successfully.")


def main() -> None:
    default_lib = _default_lib_path()
    ap = argparse.ArgumentParser(
        description=(
            "Chosen-IV adaptive exact attack on SEPAR. "
            "Searches for weak IVs, then recovers ciphertext words recursively with far fewer "
            "oracle calls than a full 2^16 codebook in the tested keys."
        )
    )

    ap.add_argument(
        "--mode",
        required=True,
        choices=["search-iv", "recover", "demo"],
        help="search-iv: search for a weak IV; recover: recover plaintext from ciphertext under a chosen IV; demo: search/attack locally and verify.",
    )
    ap.add_argument("--lib", default=default_lib, help=f"Path to SEPAR shared library (default: {default_lib})")
    ap.add_argument("--key", help="Optional key hex (64 hex chars). If omitted, the DLL built-in key is used.")
    ap.add_argument("--iv", help="IV hex (32 hex chars). Required for recover unless demo/search finds one.")
    ap.add_argument("--ciphertext", help="Ciphertext hex for recover mode.")
    ap.add_argument("--plaintext-hex", help="Plaintext hex for demo mode.")
    ap.add_argument("--demo-words", type=int, default=3, help="Random demo word count if --plaintext-hex is omitted (default: 3).")
    ap.add_argument("--search-trials", type=int, default=1000, help="Random IV trials for weak-IV search (default: 1000).")
    ap.add_argument("--score-his", default="00", help="Comma-separated upper-byte values (hex) used to score IV weakness (default: 00).")
    ap.add_argument("--stages", default="16,32,64,128,256", help="Comma-separated low-byte probe counts for adaptive narrowing (default: 16,32,64,128,256).")
    ap.add_argument("--seed", type=int, default=1, help="PRNG seed for IV search and probe ordering (default: 1).")
    ap.add_argument("--progress-every", type=int, default=100, help="Weak-IV search progress interval (default: 100).")
    ap.add_argument("--verbose-stats", action="store_true", help="Print per-word attack stats in recover mode.")

    args = ap.parse_args()

    if args.mode == "search-iv":
        run_search_iv(args)
        return
    if args.mode == "recover":
        run_recover(args)
        return
    if args.mode == "demo":
        run_demo(args)
        return

    raise SystemExit(f"Unsupported mode: {args.mode}")


if __name__ == "__main__":
    main()
