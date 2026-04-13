# Normal Inward Recursive Trials

Date: 2026-04-13

## Objective

Test the user's exact hypothesis in the strictest possible form:

- no `Delta4` / `Delta2` bridge logic
- no two-context algebra
- no extra inner-family derivation
- only the same one-context exact recursive stage scan used for `K8..K5`
- plus fresh chosen-IV trials, exactly as in the successful outward recursion search

The experiment therefore asks:

> If `K8` is already known publicly, can the identical exact recursion continue on some chosen IVs from stage `7` all the way inward through stages `4,3,2`?

Stage `1` is not part of this exact test because the existing projected-family machinery only supports stages `2..8`.

## Implementation

Added a dedicated mode to:

- [public_bridge_closure_generic_probe.c](/C:/Users/noaho/Desktop/spear/Attacks/full_key_recovery/public_bridge_closure_generic_probe.c)

Mode:

- `normal-inward`

Inputs:

- `--oracle-key HEX64`
- `--k8 K0,K1`
- `--normal-inward-trials N`
- `--seed N`

The mode runs the exact same recursive scan as the outer attack, but extended from stage `7` down to stage `2`:

1. choose a random IV
2. build the one-word codebook for that IV
3. peel with known `K8`
4. run `attacked_position_scan_exact` at stage `7`
5. if and only if the exact winner is the true `(K7,s8)`, peel and continue
6. repeat at stages `6,5,4,3,2`

This is a strict validation mode:

- if a stage has no candidate, stop
- if the exact winner is not the true pair/state, stop

So a trial only "reaches stage s" if the exact winner is correct at every stage from `7` down to `s`.

## Random-Key Target

Key:

- `2DE13EF0284A5C9BEB9FA9664ED8258BBDE5A7EA23C03CE6F3DD038E0E7570B5`

Recovered outer suffix from the public outer-half attack:

- `K8=(0E75,70B5)`
- `K7=(F3DD,038E)`
- `K6=(23C0,3CE6)`
- `K5=(BDE5,A7EA)`

True inner pairs for reference:

- `K4=(4ED8,258B)`
- `K3=(EB9F,A966)`
- `K2=(284A,5C9B)`
- `K1=(2DE1,3EF0)`

## Results

### Seed 1, 64 trials

Log:

- [normal_inward_trials64.log](/C:/Users/noaho/Desktop/spear/Attacks/full_key_recovery/normal_inward_trials64.log)

Best IV:

- `E2BCDF399A089F51F781AF9E2B179B64`

Deepest exact true recursion reached:

- stage `3`

Recovered exactly on that IV:

- `K7=(F3DD,038E), s8=DBD2`
- `K6=(23C0,3CE6), s7=2A53`
- `K5=(BDE5,A7EA), s6=177C`
- `K4=(4ED8,258B), s5=AD57`
- `K3=(EB9F,A966), s4=9A94`

Stage `2` result on that IV:

- no candidates at all (`[stage2-rot] ... candidates=0`)

### Seed 1, 256 trials

Log:

- [normal_inward_trials256.log](/C:/Users/noaho/Desktop/spear/Attacks/full_key_recovery/normal_inward_trials256.log)

Aggregate counts from the log:

- true stage-7 winner: `74`
- true stage-6 winner: `20`
- true stage-5 winner: `8`
- true stage-4 winner: `2`
- true stage-3 winner: `2`
- any stage-2 winner: `0`

So in 256 trials:

- the same recursion reached the true `K4` twice
- it reached the true `K3` twice
- it never produced a stage-2 candidate

### Seed 2, 128 trials

Log:

- [normal_inward_trials128_seed2.log](/C:/Users/noaho/Desktop/spear/Attacks/full_key_recovery/normal_inward_trials128_seed2.log)

Best IV:

- `C6B2D25F9B772DFB4D7ACF9DCBB714BF`

Deepest exact true recursion reached:

- stage `4`

Recovered exactly on that IV:

- `K7=(F3DD,038E), s8=C005`
- `K6=(23C0,3CE6), s7=5A6D`
- `K5=(BDE5,A7EA), s6=418C`
- `K4=(4ED8,258B), s5=28B4`

Aggregate counts:

- true stage-7 winner: `26`
- true stage-6 winner: `9`
- true stage-5 winner: `4`
- true stage-4 winner: `1`
- true stage-3 winner: `0`
- any stage-2 winner: `0`

## Conclusion

The user's proposed "same exact recursion only" extension is partially true.

For this random key:

- yes, the exact one-context recursion does extend beyond `K5`
- it can recover the true `K4`
- on some IVs it also recovers the true `K3`
- but in all tested trials so far it fails at stage `2`

Current exact evidence:

- `384` random IV trials across two seeds
- `3` trials reached the true `K4`
- `2` trials reached the true `K3`
- `0` trials produced any stage-2 candidate

So the clean cryptanalytic picture is:

- the inward obstruction is **not** at stage `4`
- nor necessarily at stage `3`
- the first observed hard failure of the pure single-context recursion on this random key is stage `2`

This does **not** finish the full attack by itself.

The exact same recursion machinery can carry the public attack inward to `K3` on some targets/IVs, but stage `2` still appears to require additional structure beyond the plain one-context scan.
