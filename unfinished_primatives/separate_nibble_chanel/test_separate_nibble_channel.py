import argparse
import random
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
COMMON_DIR = HERE.parent / "per_block_diff"
if str(COMMON_DIR) not in sys.path:
    sys.path.insert(0, str(COMMON_DIR))

from separ_analysis_common import S2, derive_key23, enc_block, dec_block  # noqa: E402


def nibble2(x):
    return (x >> 8) & 0xF


def lane_perm_from_abstract(beta0, beta1, beta2, beta3):
    perm = []
    for b in range(16):
        v2 = S2[b ^ beta0]
        v3 = S2[v2 ^ beta1]
        v4 = S2[v3 ^ beta2]
        v5 = S2[v4 ^ beta3]
        out = S2[v5 ^ beta0 ^ beta1] ^ beta2 ^ beta3
        perm.append(out)
    return tuple(perm)


def lane_perm_from_keypair_enc(key_pair, stage_n):
    return tuple(nibble2(enc_block(b << 8, key_pair, stage_n)) for b in range(16))


def lane_perm_from_keypair_dec(key_pair, stage_n):
    return tuple(nibble2(dec_block(b << 8, key_pair, stage_n)) for b in range(16))


def verify_enc_autonomy(rng, trials):
    for trial in range(1, trials + 1):
        key_pair = (rng.randrange(0x10000), rng.randrange(0x10000))
        for stage_n in range(1, 9):
            for b in range(16):
                expected = None
                for other in range(0x1000):
                    a = (other >> 8) & 0xF
                    c = (other >> 4) & 0xF
                    d = other & 0xF
                    x = (a << 12) | (b << 8) | (c << 4) | d
                    out = nibble2(enc_block(x, key_pair, stage_n))
                    if expected is None:
                        expected = out
                    elif out != expected:
                        raise AssertionError(
                            f"ENC autonomy failed for key=({key_pair[0]:04X},{key_pair[1]:04X}) "
                            f"stage={stage_n} b={b:X}: expected {expected:X}, got {out:X}"
                        )
        print(
            f"[enc-autonomy] trial {trial}/{trials} passed for "
            f"key=({key_pair[0]:04X},{key_pair[1]:04X})"
        )


def verify_dec_autonomy(rng, trials):
    for trial in range(1, trials + 1):
        key_pair = (rng.randrange(0x10000), rng.randrange(0x10000))
        for stage_n in range(1, 9):
            for b in range(16):
                expected = None
                for other in range(0x1000):
                    a = (other >> 8) & 0xF
                    c = (other >> 4) & 0xF
                    d = other & 0xF
                    x = (a << 12) | (b << 8) | (c << 4) | d
                    out = nibble2(dec_block(x, key_pair, stage_n))
                    if expected is None:
                        expected = out
                    elif out != expected:
                        raise AssertionError(
                            f"DEC autonomy failed for key=({key_pair[0]:04X},{key_pair[1]:04X}) "
                            f"stage={stage_n} b={b:X}: expected {expected:X}, got {out:X}"
                        )
        print(
            f"[dec-autonomy] trial {trial}/{trials} passed for "
            f"key=({key_pair[0]:04X},{key_pair[1]:04X})"
        )


def verify_formula(rng, trials):
    for trial in range(1, trials + 1):
        key_pair = (rng.randrange(0x10000), rng.randrange(0x10000))
        key0, key1 = key_pair
        for stage_n in range(1, 9):
            key2, key3 = derive_key23(key0, key1, stage_n)
            beta0 = nibble2(key0)
            beta1 = nibble2(key1)
            beta2 = nibble2(key2)
            beta3 = nibble2(key3)

            formula_perm = lane_perm_from_abstract(beta0, beta1, beta2, beta3)
            actual_perm = lane_perm_from_keypair_enc(key_pair, stage_n)
            if formula_perm != actual_perm:
                raise AssertionError(
                    f"lane formula mismatch for key=({key0:04X},{key1:04X}) stage={stage_n}"
                )
        print(
            f"[formula] trial {trial}/{trials} passed for "
            f"key=({key_pair[0]:04X},{key_pair[1]:04X})"
        )


def verify_rotor_independence(rng, trials):
    for trial in range(1, trials + 1):
        key_pair = (rng.randrange(0x10000), rng.randrange(0x10000))
        baseline = lane_perm_from_keypair_enc(key_pair, 1)
        for stage_n in range(2, 9):
            perm = lane_perm_from_keypair_enc(key_pair, stage_n)
            if perm != baseline:
                raise AssertionError(
                    f"rotor dependence found for key=({key_pair[0]:04X},{key_pair[1]:04X}) "
                    f"between stage 1 and stage {stage_n}"
                )
        print(
            f"[rotor-independence] trial {trial}/{trials} passed for "
            f"key=({key_pair[0]:04X},{key_pair[1]:04X})"
        )


def verify_abstract_injectivity():
    seen = {}
    total = 0
    for beta0 in range(16):
        for beta1 in range(16):
            for beta2 in range(16):
                for beta3 in range(16):
                    total += 1
                    perm = lane_perm_from_abstract(beta0, beta1, beta2, beta3)
                    prior = seen.get(perm)
                    if prior is not None:
                        raise AssertionError(
                            f"abstract injectivity failed: {prior} and "
                            f"({beta0},{beta1},{beta2},{beta3}) induce the same permutation"
                        )
                    seen[perm] = (beta0, beta1, beta2, beta3)
    print(f"[abstract-injectivity] passed for all {total} abstract 16-bit lane keys")


def main():
    parser = argparse.ArgumentParser(
        description="Verify the autonomous second-nibble channel primitive in SEPAR ENC_Block / DEC_Block"
    )
    parser.add_argument("--trials", type=int, default=2, help="number of random segment keys to test")
    parser.add_argument("--seed", type=int, default=0x53455041, help="PRNG seed")
    parser.add_argument(
        "--skip-injectivity",
        action="store_true",
        help="skip the exhaustive 65536-case abstract-key injectivity check",
    )
    args = parser.parse_args()

    rng = random.Random(args.seed)

    verify_enc_autonomy(rng, args.trials)
    verify_dec_autonomy(rng, args.trials)
    verify_formula(rng, args.trials)
    verify_rotor_independence(rng, args.trials)
    if not args.skip_injectivity:
        verify_abstract_injectivity()


if __name__ == "__main__":
    main()
