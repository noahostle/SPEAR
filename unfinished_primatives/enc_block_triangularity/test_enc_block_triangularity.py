import argparse
import random


S1 = [1, 15, 11, 2, 0, 3, 5, 8, 6, 9, 12, 7, 13, 10, 14, 4]
S2 = [6, 10, 15, 4, 14, 13, 9, 2, 1, 7, 12, 11, 0, 3, 5, 8]
S3 = [12, 2, 6, 1, 0, 3, 5, 8, 7, 9, 11, 14, 10, 13, 15, 4]
S4 = [13, 11, 2, 7, 0, 3, 5, 8, 6, 12, 15, 1, 10, 4, 9, 14]


def rotl16(x, y):
    y &= 15
    return ((x << y) | (x >> (16 - y))) & 0xFFFF


def do_sbox(x):
    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF
    return (S1[a] << 12) | (S2[b] << 8) | (S3[c] << 4) | S4[d]


def sep_rotl16_impl(x):
    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF

    a ^= c
    b ^= d
    c ^= b
    d ^= a

    x = (a << 12) | (b << 8) | (c << 4) | d
    return (x ^ rotl16(x, 12) ^ rotl16(x, 8)) & 0xFFFF


def sep_rotl16_closed_form(x):
    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF
    out_a = b ^ c
    out_b = b
    out_c = a
    out_d = a ^ d
    return (out_a << 12) | (out_b << 8) | (out_c << 4) | out_d


def derive_key23(key0, key1, n):
    key2 = rotl16(key0, 6)
    b = (key2 >> 6) & 0xF
    key2 |= S1[b] << 6
    key2 ^= (n + 2)
    key2 &= 0xFFFF

    key3 = rotl16(key1, 10)
    b = (key3 >> 6) & 0xF
    key3 |= S1[b] << 6
    key3 ^= (n + 3)
    key3 &= 0xFFFF

    return key2, key3


def enc_block(pt, key0, key1, n):
    key2, key3 = derive_key23(key0, key1, n)

    t = pt ^ key0
    t = do_sbox(t)
    t = sep_rotl16_impl(t)

    t ^= key1
    t = do_sbox(t)
    t = sep_rotl16_impl(t)

    t ^= key2
    t = do_sbox(t)
    t = sep_rotl16_impl(t)

    t ^= key3
    t = do_sbox(t)
    t = sep_rotl16_impl(t)

    t ^= key1 ^ key0
    t = do_sbox(t)
    t ^= key2 ^ key3
    return t & 0xFFFF


def verify_linear_layer():
    for x in range(0x10000):
        y1 = sep_rotl16_impl(x)
        y2 = sep_rotl16_closed_form(x)
        if y1 != y2:
            raise AssertionError(
                f"linear-layer mismatch at x={x:04x}: impl={y1:04x}, closed={y2:04x}"
            )
    print("[linear] exhaustive closed-form check passed for all 65536 inputs")


def verify_byte_triangularity(rng: random.Random, trials: int):
    for trial in range(1, trials + 1):
        key0 = rng.randrange(0x10000)
        key1 = rng.randrange(0x10000)

        for n in range(1, 9):
            for hi in range(0x100):
                expected = None
                for lo in range(0x100):
                    x = (hi << 8) | lo
                    out_hi = enc_block(x, key0, key1, n) >> 8
                    if expected is None:
                        expected = out_hi
                    elif out_hi != expected:
                        raise AssertionError(
                            "byte-triangularity failed for "
                            f"key=({key0:04x},{key1:04x}) n={n} hi={hi:02x}: "
                            f"expected {expected:02x}, got {out_hi:02x} at lo={lo:02x}"
                        )

        print(
            f"[byte] trial {trial}/{trials} passed for key=({key0:04x},{key1:04x}) "
            "across all 8 rotor indices and all 65536 inputs"
        )


def verify_second_nibble_lane(rng: random.Random, trials: int):
    for trial in range(1, trials + 1):
        key0 = rng.randrange(0x10000)
        key1 = rng.randrange(0x10000)

        for n in range(1, 9):
            for nibble2 in range(16):
                expected = None
                for other in range(0x1000):
                    a = (other >> 8) & 0xF
                    c = (other >> 4) & 0xF
                    d = other & 0xF
                    x = (a << 12) | (nibble2 << 8) | (c << 4) | d
                    out_nibble2 = (enc_block(x, key0, key1, n) >> 8) & 0xF
                    if expected is None:
                        expected = out_nibble2
                    elif out_nibble2 != expected:
                        raise AssertionError(
                            "second-nibble autonomy failed for "
                            f"key=({key0:04x},{key1:04x}) n={n} b={nibble2:x}: "
                            f"expected {expected:x}, got {out_nibble2:x}"
                        )

        print(
            f"[nibble] trial {trial}/{trials} passed for key=({key0:04x},{key1:04x}) "
            "across all 8 rotor indices"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Verify the exact byte-triangular collapse of SEPAR ENC_Block"
    )
    parser.add_argument("--trials", type=int, default=4, help="number of random segment keys to test")
    parser.add_argument("--seed", type=int, default=0x53455041, help="PRNG seed")
    parser.add_argument(
        "--check-nibble-lane",
        action="store_true",
        help="also verify the stronger autonomous second-nibble property",
    )
    args = parser.parse_args()

    rng = random.Random(args.seed)
    verify_linear_layer()
    verify_byte_triangularity(rng, args.trials)
    if args.check_nibble_lane:
        verify_second_nibble_lane(rng, args.trials)


if __name__ == "__main__":
    main()
