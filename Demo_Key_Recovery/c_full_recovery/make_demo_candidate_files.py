from __future__ import annotations

from pathlib import Path

from stage_peel_attack import candidate_key_pool, index_from_keypair


def main() -> None:
    outdir = Path("demo_candidate_files")
    outdir.mkdir(exist_ok=True)
    pools = candidate_key_pool(3, 0)
    for stage in range(1, 9):
        with (outdir / f"stage{stage}.tsv").open("w", encoding="ascii") as f:
            f.write("# score\tindex\tbest_low\tkeypair\n")
            for keypair in pools[stage]:
                index = index_from_keypair(keypair)
                f.write(
                    f"0\t0x{index:08X}\t0x00\t{keypair[0]:04X}{keypair[1]:04X}\n"
                )
    print(f"wrote demo candidate files to {outdir}")


if __name__ == "__main__":
    main()
