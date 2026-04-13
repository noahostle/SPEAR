# SEPAR Public Outer-Half Hybrid Attack

## Scope

This note describes the combined public attack implemented in:

- [separ_public_outer_hybrid_attack.c](/C:/Users/noaho/Desktop/upload/separ_public_outer_hybrid_attack.c)
- [separ_public_outer_hybrid_attack.exe](/C:/Users/noaho/Desktop/upload/separ_public_outer_hybrid_attack.exe)

The attack recovers the outer suffix

```text
K8, K7, K6, K5
```

and the corresponding hidden state words

```text
s8, s7, s6
```

from chosen-IV chosen-plaintext access to the implemented cipher, using only public ciphertext tables derived from the oracle. No hidden state, no true-candidate injection, and no resumed inner-stage data are used.

This is an **outer-half** attack. It does not include the inner `K4..K1` bridge closure.

## Model

Fix an IV-dependent one-word encryption table

```text
F_IV(x) = SEPAR_Enc_IV(x).
```

For any stage pair `Kr = (kr, kr')`, write `Er` for the stage encryption permutation and `Dr` for its inverse.

The implemented public attack uses the default exact additive difference set

```text
Delta = {0001, 0002, 0004, 0008, 000F, 0010}.
```

## Phase 1: Weak-IV Beam Search

The first phase searches chosen IVs whose public one-word table has weak upper-byte branching. The metric is the exact row-branching score already used in the earlier Hummingbird-style work:

```text
rho(IV) = chosen_iv_row_score_table(F_IV).
```

The executable samples `search_trials` random IVs, keeps the `search_beam` best by `rho`, and uses those as the candidate beam for the combined outer attack.

This is implemented by:

- `search_weak_ivs`
- `weak_iv_candidate_insert`

in [separ_public_outer_hybrid_attack.c](/C:/Users/noaho/Desktop/upload/separ_public_outer_hybrid_attack.c).

## Phase 2: Exact Quotient Bootstrap for `K8`

On each beam IV, the attack first runs the exact projected-cycle bootstrap already used by the standalone quotient attack.

For the observed ciphertext table `F_IV`, it computes the exact maximum projected stage-8 cycles by scoring visible upper-nibble transitions:

```text
score_proj(c) = sum_{(a -> b) on c} M[a,b]
```

where `M[a,b]` counts how often the upper nibble of `F_IV(x)` is `a` and the upper nibble of `F_IV(x+d)` is `b`, summed over `d in Delta`.

The code path is:

- `stage8_group_mass_u16`
- `exact_max_projected_cycles`
- `run_stage8_bootstrap_exact`

The bootstrap then reconstructs a full 8-bit order by exact Hungarian matching and enumerates all `K8` candidates compatible with the winning projected cycle.

On the canonical weak target, this already recovers the true `K8` directly.

## Phase 3: Hybrid Closure of the Quotient Output

On non-canonical keys, the quotient bootstrap can miss the true `K8` while still localizing it to a tiny coarse coset.

Empirically, the failure pattern is highly structured. If the quotient bootstrap emits

```text
S_IV = { (k0, k1) } ,
```

the true key often lies in the closure of `S_IV` under independent top-bit toggles of the two 16-bit words:

```text
(k0, k1)
(k0 xor 8000, k1)
(k0, k1 xor 8000)
(k0 xor 8000, k1 xor 8000).
```

The implementation forms that closure in:

- `expand_k8_toggle_pool`

For each candidate `K8` in that tiny closure, it computes the exact additive differential score

```text
sigma_IV(K8)
= sum_{d in Delta} max_b |{ x : D8(F_IV(x+d); K8) - D8(F_IV(x); K8) = b }|.
```

This is implemented in:

- `stage8_additive_differential_score`

The score is exact and offline: the whole `2^16` table is available, and the stage translation cancels from the additive differential.

Across the weak-IV beam, the script aggregates those exact scores:

```text
Sigma(K8) = sum_{IV in beam} sigma_IV(K8)
```

restricted to candidates that appear in the toggle-closure pool for at least one beam IV.

This is implemented by:

- `recover_k8_hybrid_from_beam`
- `k8_aggregate_add`

The winning aggregate candidate is the recovered public `K8`.

## Phase 4: Exact Public Recursion from Known `K8`

Once `K8` is known, the attack peels the last visible stage and recovers `(K7, s8)`, `(K6, s7)`, `(K5, s6)` recursively by exact state recovery.

For stage `r in {7,6,5}`:

1. Peel the known outer suffix from the current table.
2. Recover the low byte of the hidden translation by exact support collapse.
3. Enumerate the exact projected-cycle maxima.
4. Reconstruct the order.
5. Enumerate all exact candidate pairs and exact state words.
6. Select the best exact verifier.

That logic is implemented by:

- `recursive_public_context_recovery_exact`
- `attacked_position_scan_exact`

and the underlying cycle/order/state routines it calls.

## Phase 5: Exact Search for a Recursion IV

The weak-IV beam is chosen to make the stage-8 hybrid easy. That beam does not necessarily contain an IV on which the known-`K8` recursion continues through `K5`.

So the combined public attack adds a final exact search phase:

1. recover `K8` from the weak-IV beam,
2. test the beam IVs for exact public recursion from that `K8`,
3. if none succeed, scan fresh random IVs and stop at the first IV for which the exact public recursion reaches `K5`.

This search is still public and exact. The success predicate is literally the recursion itself; there is no heuristic filter at this phase.

The implementation is:

- `probe_outer_recursion_with_known_k8`
- `run_outer_attack_beam_hybrid`

## Executable Behavior

### Direct quotient mode

With a fixed IV and no search arguments, the executable runs the original fast quotient recursion:

```text
separ_public_outer_hybrid_attack.exe full --workers 16
```

### Combined public mode

With `--search-trials`, the executable runs the full combined public outer attack:

1. weak-IV beam search,
2. hybrid `K8` recovery,
3. exact public recursion search to `K5`.

Example:

```text
separ_public_outer_hybrid_attack.exe full --search-trials 512 --search-beam 16 --workers 16 --oracle-key <64-hex-key>
```

## Worked Example 1: Canonical Target

The canonical direct run is logged in:

- [separ_public_outer_hybrid_attack_canonical.log](/C:/Users/noaho/Desktop/upload/separ_public_outer_hybrid_attack_canonical.log)

Observed result:

```text
K8=(FC7D,6371)
K7=(8D1E,9DF5), s8=2B69
K6=(F44A,233E), s7=C29E
K5=(50C5,12DB), s6=8E72.
```

The outer half is recovered in about ten seconds on the canonical weak target.

## Worked Example 2: Random Key

Random full key:

```text
2DE13EF0284A5C9BEB9FA9664ED8258BBDE5A7EA23C03CE6F3DD038E0E7570B5
```

The combined public search is logged in:

- [separ_public_outer_hybrid_attack_randomkey_v2.log](/C:/Users/noaho/Desktop/upload/separ_public_outer_hybrid_attack_randomkey_v2.log)

### Stage-8 hybrid recovery

On this key, the direct quotient bootstrap is not generic enough. The weak-IV beam contains several IVs on which the quotient bootstrap returns the small false class

```text
(8E74,F0B5), (8E75,F0B5), (8E76,F0B5)
```

but the hybrid exact differential aggregate corrects this to

```text
K8 = (0E75,70B5).
```

The log shows:

```text
[hybrid-k8] winner=(0E75,70B5) aggregate_score=7995 hits=5
```

### Exact recursion-IV search

The weak-IV beam itself does not reach `K5`, so the script continues to the exact public recursion-IV search and finds, at trial `40`,

```text
IV = 5CA4F8C38EF73F65D500570F0F9BA5E7.
```

On that IV, the recovered outer suffix is:

```text
K8=(0E75,70B5)
K7=(F3DD,038E), s8=B38F
K6=(23C0,3CE6), s7=8375
K5=(BDE5,A7EA), s6=4D7E.
```

The focused debug validation is logged in:

- [separ_public_outer_hybrid_attack_found_iv_debug.log](/C:/Users/noaho/Desktop/upload/separ_public_outer_hybrid_attack_found_iv_debug.log)

and confirms:

```text
branch 1 outer-match=yes
```

so this is an exact public outer-half recovery on that random key.

## Complexity

Let `B` be the weak-IV beam size and `T` the number of random IV trials.

The main costs are:

1. Weak-IV beam search:

```text
T * 2^16
```

one-word encryptions.

2. Stage-8 quotient bootstrap on each beam IV:

```text
B * (rep-table work + exact cycle scan + exact candidate verification).
```

The representative tables are cached, so only the first call builds them.

3. Hybrid stage-8 rescoring:

If each IV contributes a small closure pool of size `m`, the exact cost is

```text
B * m * |Delta| * 2^16.
```

In practice `m` is tiny; in the tested random-key case `m = 12`.

4. Known-`K8` recursion-IV search:

Each trial runs the exact public recursion from `K8` down to `K5` and stops at the first failure or success.

So the attack is practical because:

- the stage-8 hybrid reduces `K8` to a tiny exact candidate pool,
- the recursion search only needs to find one good IV,
- every inner step of the outer-half recursion is exact.

## What This Script Does Not Claim

This executable does **not** solve the inner half `K4..K1`.

It is the combined public outer-half attack only:

```text
K8 -> K5
```

with:

- exact quotient/bootstrap machinery,
- exact hybrid stage-8 differential correction,
- exact public recursion from known `K8`,
- exact public IV search for a recursion context.

That is the correct scope of the implementation currently placed in `Desktop/upload`.
