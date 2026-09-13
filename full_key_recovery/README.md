# SEPAR key-recovery attack

This directory contains the final paper, the threaded proof-of-concept attack,
the SEPAR reference implementation, and the minimal data supporting the
reported experiment.

The attack applies in the repeated-reset chosen-IV setting: the attacker can
select or reuse the 128-bit IV and obtain fresh encryptions from the resulting
initial state. It is not a nonce-respecting attack.

## Contents

- `paper.pdf` and `paper.tex`: the paper and its LaTeX source.
- `code/separ_attack.c`: the complete threaded outer-to-inward attack.
- `reference/separ.c`: the analyzed SEPAR implementation.
- `results/trials.csv`: one row for each of the 100 evaluation keys.
- `results/summary.md`: experimental setup and aggregate results.
- `results/logs/`: representative phase-level records from the evaluation.

## Build and test

The program requires a C11 compiler and POSIX threads.

```sh
cd code
make
make test
```

`make test` checks the cipher operations, quotient formula, lane injectivity,
carry filters, pivot induction, threaded ordering, and a complete recovery.
It takes several minutes.

The default published example can be run as follows:

```sh
./separ_attack E8B9B733DA5D96D702DD3972E95307FD50C512DBF44A233E8D1E9DF5FC7D6371
```

This one command constructs the local chosen-IV oracle from the supplied demo
key, runs the outer prefix attack, hands the selected `K8` directly to inward
recovery, and verifies the recovered key against all cached codebooks and two
held-out transcripts. It should finish with `FULL_ATTACK_RESULT=SUCCESS`.

The sole attack argument is exactly 64 hexadecimal characters. It is used only
by the local demonstration oracle to generate public chosen-plaintext replies;
candidate ordering and acceptance use those replies. `DEMO_EXACT` compares the
verified result with the demo key only after the attack has accepted it.

The demo uses the highest-scoring outer lane and one score tier at each inward
ranking level, matching the practical bounded attack. A ranking miss exits with
status 2 and reports `INCONCLUSIVE`; it is not evidence that exhaustive search
would fail. The paper proves completeness for the conceptual traversal that
visits every outer fibre and every inward tier.

## Paper

With a standard TeX installation, rebuild the paper from this directory with:

```sh
latexmk -pdf -interaction=nonstopmode -halt-on-error paper.tex
```

The evaluation data and statistical interpretation are summarized in
`results/summary.md`.
