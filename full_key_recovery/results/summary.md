# Evaluation summary

The same fixed list of 100 distinct 256-bit keys, generated before the
evaluation with the operating system random generator, was used for both
phases.  `trials.csv` joins the two records by trial number and checks the full
key and the final 32-bit word (K_8) for equality before merging them.

## Protocol

The outer experiment used eight threads, the fixed IV
`5CC1EC67555EC90BB5B902803CA58575`, and the first four score-ordered lane
positions.  A trial succeeded when the true (K_8) was emitted within that
budget.  Each
cached experiment used 458,752 reset messages containing 917,504 words.

The inward experiment used eight threads, eight reset codebooks selected with
seed 1, and one score tier at each of the lane, pair, and state rankings.  Each
trial was given the true (K_8), so this experiment measures inward recovery
conditional on a correct outer candidate.  It used 524,290 reset messages and
524,416 encrypted words, including two held-out verification messages.  The
per-trial timeout was 600 seconds.  A strict success required normal exit,
exact recovery of the 256-bit key, successful codebook and held-out
verification, and a well-formed terminal success record.

The joint result is the Boolean intersection of outer and inward strict success
for the same key.  It is not the product of two estimated rates.

## Results

| measurement | successes | exact two-sided 95% Clopper--Pearson interval | exact one-sided 95% failure upper bound |
|---|---:|---:|---:|
| outer (K_8) bootstrap | 100/100 | [0.9637833074, 1] | 0.0295130496 |
| inward recovery, given (K_8) | 95/100 | [0.8871650889, 0.9835681208] | 0.1022533776 |
| matched-key conjunction | 95/100 | [0.8871650889, 0.9835681208] | 0.1022533776 |

Wall-clock timings were as follows.  The 95th percentile is the nearest-rank
sample quantile.

| sample | minimum | median | mean | 95th percentile | maximum |
|---|---:|---:|---:|---:|---:|
| outer, all 100 trials | 0.127706 s | 0.282069 s | 0.353935 s | 0.649831 s | 0.710156 s |
| inward, all 100 trials | 3.982283 s | 180.950255 s | 187.000431 s | 285.745932 s | 600.081318 s |
| inward, 95 successes | 73.514882 s | 181.067530 s | 183.437625 s | 284.051591 s | 326.892763 s |

All 100 true outer lanes were in the first score tier.  The inward experiment
returned 95 successes, three inconclusive results, and two timeouts.  Every
miss occurred because the true (S_4) lane lay outside the one-tier budget:

| trial | outcome | first missed ranking |
|---:|---|---|
| 15 | INCONCLUSIVE | stage 6, tier 3 |
| 50 | TIMEOUT | stage 7, tier 8 |
| 54 | TIMEOUT | stage 7, tier 9 |
| 89 | INCONCLUSIVE | stage 7, tier 4 |
| 91 | INCONCLUSIVE | stage 7, tier 2 |

Whenever they were reached, the true pair, byte, and state candidates were all
in their first score tier.  Those rank observations are correlated within a
trial and are censored when a run terminates early; they are useful diagnostics,
not independent probability estimates.

## Scope of the statistics

The binomial intervals have their stated coverage if the predetermined keys
are independent draws from the population of interest.  Distinctness alone is
not enough to establish that premise.  The inward rate is conditional on the
correct (K_8); the matched-key conjunction does not replay the inward search
for false outer candidates that precede the true one, and no end-to-end latency
was measured in the 100-key evaluation.  Timings are for the local-oracle
implementation and are
machine-, compiler-, and thread-scheduling-dependent.  The attack also assumes
the repeated-reset, chosen-IV interface described in the paper; these results
do not apply directly to a nonce-respecting interface.

## `trials.csv` columns

- `trial`: one-based trial number.
- `key_hex`: tested 256-bit key in hexadecimal.
- `k8_hex`: final 32-bit key word supplied to the inward phase.
- `outer_success`: 1 exactly when the outer strict-success condition held.
- `true_lane_rank`: one-based position of the true outer lane after sorting by
  score and the deterministic tie rule.
- `outer_wall_seconds`: measured wall time for the outer phase.
- `inward_outcome`: terminal inward classification (`SUCCESS`,
  `INCONCLUSIVE`, or `TIMEOUT`).
- `inward_success`: 1 exactly when the inward strict-success condition held.
- `inward_wall_seconds`: measured wall time for the inward phase.
- `first_tier_failure`: first true candidate outside its configured tier
  budget, or empty on success.  For example, `S4:s6:c0:tier3` denotes the
  stage-6 (S_4) lane score in tier 3; context zero marks a stage-wide ranking.
- `joint_success`: `outer_success AND inward_success` on the same key.

The three logs in `logs/` show one successful outer bootstrap, one successful
inward recovery, and the trial-15 (S_4) rank miss from the phase-level
evaluation.
