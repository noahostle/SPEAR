# SEPAR key-recovery attack

This directory contains the final paper, the threaded proof-of-concept attack,
the SEPAR reference implementation, and the minimal data supporting the
reported experiment.

The attack applies in the repeated-reset chosen-IV setting: the attacker can
select or reuse the 128-bit IV and obtain fresh encryptions from the resulting
initial state. It is not a nonce-respecting attack.

## Contents

- `paper.pdf` and `paper.tex`: the paper and its LaTeX source.
- `code/separ_prefix_attack.c`: fixed-IV outer recovery of the last key pair.
- `code/separ_ranked_inward.c`: multi-IV inward recovery of the other pairs.
- `code/separ_common.h`: shared cipher and attack primitives.
- `reference/separ.c`: the analyzed SEPAR implementation.
- `results/trials.csv`: one row for each of the 100 evaluation keys.
- `results/summary.md`: experimental setup and aggregate results.
- `results/logs/`: one outer success, one inward success, and one bounded miss.

## Build and test

The programs require a C11 compiler and POSIX threads.

```sh
cd code
make
make test
```

`make test` checks the cipher operations, quotient formula, lane injectivity,
carry filters, pivot induction, threaded ordering, outer recovery, exhaustive
fallback coverage, and a complete inward recovery. It takes several minutes.
The slower `make hard-test` additionally exercises context retirement.

The default published example can be run as follows:

```sh
./separ_prefix_attack --threads 8 --top 1
./separ_ranked_inward --known-k8 FC7D6371 --threads 8 \
    --contexts 8 --seed 1 --lane-tiers 1 --pair-tiers 1 --state-tiers 1
```

The outer program should report `candidate_K8=(FC7D,6371)`. The inward program
then verifies and reports the published 256-bit example key.

Both programs include a local oracle so that the experiment is self-contained.
`--key` and `--iv` select the outer simulated secret and IV;
`--oracle-key` selects the inward simulated secret. These values generate the
public chosen-plaintext transcripts and are not used by candidate acceptance.
`--audit` prints truth-relative diagnostics only.

A bounded inward miss exits with status 2 and reports `INCONCLUSIVE`.
`--complete` sets every inward tier budget to zero and disables retirement, but
the executable still stops at the first transcript-consistent key. The paper's
completeness theorem concerns the conceptual traversal continued through all
finite candidates. Complete outer traversal is obtained by visiting
`--lane-rank 1` through `65536` and using `--emit-fallback` for every selected
fibre; no wrapper is needed for the bounded experiment reported here.

## Paper

With a standard TeX installation, rebuild the paper from this directory with:

```sh
latexmk -pdf -interaction=nonstopmode -halt-on-error paper.tex
```

The evaluation data and statistical interpretation are summarized in
`results/summary.md`.
