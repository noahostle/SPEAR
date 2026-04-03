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
)


DEFAULT_DIFFS = [0x0001, 0x0002, 0x0004, 0x0008, 0x000F, 0x0010]


def candidate_score(peeled_table, diffs):
    score = 0
    per_diff = []
    for input_diff in diffs:
        hits = scan_table_for_input_diff(peeled_table, input_diff, "add", topn=1)
        best_count, best_out = hits[0]
        score += best_count
        per_diff.append((input_diff, best_out, best_count))
    return score, per_diff


def main():
    parser = argparse.ArgumentParser(
        description="Score K8 guesses by additive-differential consistency on a matched-context codebook"
    )
    parser.add_argument(
        "--prefix",
        default="2028",
        help="comma-separated plaintext prefix words in hex; the scanned codebook is for the next word",
    )
    parser.add_argument(
        "--diffs",
        default=",".join(f"{d:04x}" for d in DEFAULT_DIFFS),
        help="comma-separated additive input differences in hex",
    )
    parser.add_argument(
        "--candidate",
        action="append",
        default=[],
        help="candidate K8 as k0,k1 in hex; may be passed multiple times",
    )
    parser.add_argument(
        "--random-candidates",
        type=int,
        default=0,
        help="append this many random wrong candidate key pairs",
    )
    parser.add_argument("--seed", type=int, default=0x53455041, help="PRNG seed for random candidate generation")
    parser.add_argument(
        "--key",
        help="optional 64-hex full key; if omitted the built-in default key is used",
    )
    parser.add_argument(
        "--iv",
        help="optional 32-hex IV; if omitted the built-in zero IV is used",
    )
    parser.add_argument(
        "--include-correct",
        action="store_true",
        help="explicitly include the true K8 from --key or the built-in default key",
    )
    args = parser.parse_args()

    prefix_words = parse_word_list(args.prefix)
    diffs = parse_word_list(args.diffs)
    if not prefix_words:
        raise SystemExit("prefix must contain at least one 16-bit word")
    if not diffs:
        raise SystemExit("diffs must contain at least one additive input difference")

    key_words = parse_full_key_hex(args.key) if args.key else list(DEFAULT_KEY)
    iv_words = parse_full_iv_hex(args.iv) if args.iv else list(DEFAULT_IV)
    correct_k8 = (key_words[14], key_words[15])

    candidates = []
    seen = set()

    def add_candidate(pair):
        if pair not in seen:
            seen.add(pair)
            candidates.append(pair)

    for candidate_text in args.candidate:
        add_candidate(parse_key_pair(candidate_text))
    if args.include_correct or not candidates:
        add_candidate(correct_k8)

    rng = random.Random(args.seed)
    target_count = len(candidates) + args.random_candidates
    while len(candidates) < target_count:
        pair = (rng.randrange(0x10000), rng.randrange(0x10000))
        if pair != correct_k8:
            add_candidate(pair)

    prefix_ct, codebook = build_matched_context_codebook(prefix_words, key_words, iv_words)

    print("Matched-context K8 differential scan")
    print(f"  prefix_pt = {[f'{w:04X}' for w in prefix_words]}")
    print(f"  prefix_ct = {[f'{w:04X}' for w in prefix_ct]}")
    print(f"  diffs     = {', '.join(f'{d:04X}' for d in diffs)}")
    print(f"  true_K8   = ({correct_k8[0]:04X}, {correct_k8[1]:04X})")
    print()

    ranked = []
    for pair in candidates:
        peeled_table = [dec_block(y, pair, 8) for y in codebook]
        score, per_diff = candidate_score(peeled_table, diffs)
        ranked.append((score, pair, per_diff))

    ranked.sort(key=lambda item: (-item[0], item[1]))

    for rank, (score, pair, per_diff) in enumerate(ranked, start=1):
        marker = "  <-- true K8" if pair == correct_k8 else ""
        print(f"#{rank}: K8=({pair[0]:04X}, {pair[1]:04X}) score={score}{marker}")
        for input_diff, best_out, best_count in per_diff:
            print(
                f"    add in={input_diff:04X} best out={best_out:04X} "
                f"count={best_count} prob={best_count / 65536.0:.8f}"
            )
        print()


if __name__ == "__main__":
    main()
