import argparse

from separ_analysis_common import (
    best_count,
    build_table_from_function,
    enc_block,
    parse_hex_word,
    parse_key_pair,
    parse_word_list,
    scan_table_for_input_diff,
)


DEFAULT_DIFFS = [0x0001, 0x0002, 0x0004, 0x0008, 0x000F, 0x0010]


def format_hits(hits):
    parts = []
    for count, out_diff in hits:
        parts.append(f"{out_diff:04X}:{count} ({count / 65536.0:.8f})")
    return ", ".join(parts)


def main():
    parser = argparse.ArgumentParser(
        description="Exact differential scanner for the implemented SEPAR ENC_Block"
    )
    parser.add_argument("--key-pair", default="fc7d,6371", help="segment key as k0,k1 in hex")
    parser.add_argument("--stage", type=int, default=8, help="stage index n in ENC_Block(..., n)")
    parser.add_argument(
        "--mode",
        choices=["xor", "add", "both"],
        default="both",
        help="difference mode to scan",
    )
    parser.add_argument(
        "--diffs",
        default=",".join(f"{d:04x}" for d in DEFAULT_DIFFS),
        help="comma-separated input differences in hex",
    )
    parser.add_argument("--topn", type=int, default=5, help="number of top outputs to print per input diff")
    parser.add_argument(
        "--all-low-nibble",
        action="store_true",
        help="scan all nonzero low-nibble differences 0001..000F",
    )
    args = parser.parse_args()

    key_pair = parse_key_pair(args.key_pair)
    diffs = list(range(1, 0x10)) if args.all_low_nibble else parse_word_list(args.diffs)
    if not diffs:
        raise SystemExit("no input differences selected")
    if not (1 <= args.stage <= 8):
        raise SystemExit("stage must be in 1..8")

    table = build_table_from_function(lambda x: enc_block(x, key_pair, args.stage))

    print(f"ENC_Block differential scan")
    print(f"  key_pair = ({key_pair[0]:04X}, {key_pair[1]:04X})")
    print(f"  stage    = {args.stage}")
    print(f"  diffs    = {', '.join(f'{d:04X}' for d in diffs)}")
    print()

    modes = ["xor", "add"] if args.mode == "both" else [args.mode]
    for mode in modes:
        print(f"[{mode.upper()}]")
        global_best = None
        for input_diff in diffs:
            hits = scan_table_for_input_diff(table, input_diff, mode, args.topn)
            print(f"  in={input_diff:04X} -> {format_hits(hits)}")
            if global_best is None or hits[0][0] > global_best[0]:
                global_best = (hits[0][0], input_diff, hits[0][1])
        best_count_value, best_in, best_out = global_best
        print(
            f"  strongest scanned cell: in={best_in:04X} out={best_out:04X} "
            f"count={best_count_value} prob={best_count_value / 65536.0:.8f}"
        )
        print()


if __name__ == "__main__":
    main()
