import argparse
import random

from separ_analysis_common import (
    DEFAULT_IV,
    DEFAULT_KEY,
    build_matched_context_codebook,
    dec_block,
    parse_full_iv_hex,
    parse_full_key_hex,
    parse_key_pair,
    parse_word_list,
    scan_table_for_input_diff,
    separ_ctx_after_prefix,
)


DEFAULT_PREFIX = "2028"
DEFAULT_HIS = [0x00, 0x40, 0x80, 0xC0]
DEFAULT_DIFFS = [0x0001, 0x0002, 0x0004, 0x0008, 0x000F, 0x0010]


def support_lowbyte_score(peeled_k8_table, low_byte, his):
    score = 0
    for hi in his:
        seen = set()
        base = hi << 8
        for lo in range(0x100):
            word = (peeled_k8_table[base | lo] - low_byte) & 0xFFFF
            seen.add((word >> 8) & 0xFF)
        score += len(seen)
    return score


def additive_score(table, diffs):
    score = 0
    per_diff = []
    for input_diff in diffs:
        best_count, best_out = scan_table_for_input_diff(table, input_diff, "add", topn=1)[0]
        score += best_count
        per_diff.append((input_diff, best_out, best_count))
    return score, per_diff


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Recover s8 after K8 by splitting the 16-bit translation search into "
            "a low-byte support scan and a high-byte stage-7 differential consistency scan"
        )
    )
    parser.add_argument(
        "--prefix",
        default=DEFAULT_PREFIX,
        help="comma-separated plaintext prefix words in hex; lambda is scanned for the next word context",
    )
    parser.add_argument(
        "--k8",
        default=None,
        help="known or hypothesized K8 as k0,k1 in hex; defaults to the true K8 from --key or the built-in key",
    )
    parser.add_argument(
        "--k7-candidate",
        action="append",
        default=[],
        help="candidate K7 as k0,k1 in hex; may be passed multiple times",
    )
    parser.add_argument(
        "--random-k7-candidates",
        type=int,
        default=0,
        help="append this many random K7 candidates",
    )
    parser.add_argument("--seed", type=int, default=0x53455041, help="PRNG seed for random K7 generation")
    parser.add_argument(
        "--key",
        help="optional 64-hex full key; if omitted the built-in default key is used",
    )
    parser.add_argument(
        "--iv",
        help="optional 32-hex IV; if omitted the built-in zero IV is used",
    )
    parser.add_argument(
        "--include-correct-k7",
        action="store_true",
        help="include the true K7 from --key or the built-in key in the candidate set",
    )
    parser.add_argument(
        "--support-his",
        default="00,40,80,c0",
        help="upper-byte classes used in the low-byte support scan",
    )
    parser.add_argument(
        "--diffs",
        default=",".join(f"{d:04x}" for d in DEFAULT_DIFFS),
        help="comma-separated additive input differences used in the high-byte scan",
    )
    parser.add_argument("--top-low", type=int, default=1, help="number of best low-byte candidates to refine")
    parser.add_argument("--topn", type=int, default=12, help="number of best full lambda candidates to print")
    args = parser.parse_args()

    prefix_words = parse_word_list(args.prefix)
    his = parse_word_list(args.support_his)
    diffs = parse_word_list(args.diffs)
    if not prefix_words:
        raise SystemExit("prefix must contain at least one 16-bit word")
    if not his:
        raise SystemExit("support-his must contain at least one byte value")
    if not diffs:
        raise SystemExit("diffs must contain at least one additive input difference")
    if any(h > 0xFF for h in his):
        raise SystemExit("support-his entries must be byte-sized values")

    key_words = parse_full_key_hex(args.key) if args.key else list(DEFAULT_KEY)
    iv_words = parse_full_iv_hex(args.iv) if args.iv else list(DEFAULT_IV)
    true_k8 = (key_words[14], key_words[15])
    true_k7 = (key_words[12], key_words[13])
    k8_pair = parse_key_pair(args.k8) if args.k8 else true_k8

    k7_candidates = []
    seen = set()

    def add_k7(pair):
        if pair not in seen:
            seen.add(pair)
            k7_candidates.append(pair)

    for text in args.k7_candidate:
        add_k7(parse_key_pair(text))
    if args.include_correct_k7 or not k7_candidates:
        add_k7(true_k7)

    rng = random.Random(args.seed)
    target_count = len(k7_candidates) + args.random_k7_candidates
    while len(k7_candidates) < target_count:
        add_k7((rng.randrange(0x10000), rng.randrange(0x10000)))

    prefix_ct, codebook = build_matched_context_codebook(prefix_words, key_words, iv_words)
    peeled_k8 = [dec_block(y, k8_pair, 8) for y in codebook]
    ctx = separ_ctx_after_prefix(prefix_words, key_words, iv_words)
    true_s8 = ctx["state"][7]

    print("Matched-context s8 scan")
    print(f"  prefix_pt   = {[f'{w:04X}' for w in prefix_words]}")
    print(f"  prefix_ct   = {[f'{w:04X}' for w in prefix_ct]}")
    print(f"  K8          = ({k8_pair[0]:04X}, {k8_pair[1]:04X})")
    print(f"  true_s8     = {true_s8:04X}")
    print(f"  true_K7     = ({true_k7[0]:04X}, {true_k7[1]:04X})")
    print(f"  support_his = {', '.join(f'{h:02X}' for h in his)}")
    print(f"  diffs       = {', '.join(f'{d:04X}' for d in diffs)}")
    print()

    low_ranked = []
    for low_byte in range(0x100):
        low_score = support_lowbyte_score(peeled_k8, low_byte, his)
        low_ranked.append((low_score, low_byte))
    low_ranked.sort(key=lambda item: (item[0], item[1]))

    print("Top low-byte candidates from support scan:")
    for rank, (low_score, low_byte) in enumerate(low_ranked[: args.top_low], start=1):
        marker = "  <-- true low byte" if low_byte == (true_s8 & 0xFF) else ""
        print(f"  #{rank}: low={low_byte:02X} support_score={low_score}{marker}")
    print()

    k7_tables = [(pair, [dec_block(z, pair, 7) for z in range(0x10000)]) for pair in k7_candidates]

    ranked = []
    for _, low_byte in low_ranked[: args.top_low]:
        for high_byte in range(0x100):
            lambda_value = (high_byte << 8) | low_byte
            best = None
            best_per_diff = None
            for pair, table7 in k7_tables:
                reduced6 = [table7[(value - lambda_value) & 0xFFFF] for value in peeled_k8]
                score, per_diff = additive_score(reduced6, diffs)
                entry = (-score, pair)
                if best is None or entry < best:
                    best = entry
                    best_per_diff = per_diff
            ranked.append((-best[0], lambda_value, best[1], best_per_diff))

    ranked.sort(key=lambda item: (-item[0], item[1]))

    print("Top full lambda candidates after stage-7 differential refinement:")
    for rank, (score, lambda_value, best_k7, per_diff) in enumerate(ranked[: args.topn], start=1):
        marker = "  <-- true s8" if lambda_value == true_s8 else ""
        k7_marker = "  [true K7]" if best_k7 == true_k7 else ""
        print(
            f"#{rank}: lambda={lambda_value:04X} score={score} "
            f"best_K7=({best_k7[0]:04X}, {best_k7[1]:04X}){k7_marker}{marker}"
        )
        for input_diff, best_out, best_count in per_diff:
            print(
                f"    add in={input_diff:04X} best out={best_out:04X} "
                f"count={best_count} prob={best_count / 65536.0:.8f}"
            )
        print()


if __name__ == "__main__":
    main()
