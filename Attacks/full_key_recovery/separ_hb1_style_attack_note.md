# Hummingbird-Style Stage-Peel Attack on the SEPAR Implementation

## Executive summary

The implementation in [`SEPAR/main.c`](C:/Users/noaho/Desktop/spear/SEPAR/main.c) contains a devastating diffusion bug in `Sep_ROTL16()`.

Instead of behaving like the paper's intended 16-bit mixing layer, the implemented map simplifies exactly to

```text
L(a, b, c, d) = (b xor c, b, a, a xor d)
```

on nibble inputs `(a, b, c, d)`.

That creates three implementation-specific failures:

1. Every `ENC_Block` is exactly byte-triangular.
2. The second nibble is an autonomous 4-bit keyed channel.
3. Chosen-prefix encryption and decryption give an exact matched forward/inverse permutation oracle for the next 16-bit word.

Together these turn SEPAR into a Hummingbird-1-style "peel the outer keyed box, then recurse" target.

The strongest fully verified practical result is:

- chosen-IV weak-context search finds IVs for which the exposed next-word permutation is far more triangular than random
- on such an IV, the outer segment key `K8` is recovered cleanly by exact offline differential scoring
- chosen-ciphertext / inverse weak-context search does the same for `K1`
- the hidden low byte of `state_8` is recovered from the peeled table by a simple row-branching score
- after stripping both ends of the exposed permutation, the same scoring starts exposing `K7`
- after one more exact right-side peel, `K6` can already be made to separate by a huge margin in some contexts

The recursive framework is real. The remaining work is automating the left-side gauge recovery cleanly enough to make the full 256-bit recovery fully push-button.

## 1. The fatal implementation error

The core bug is in `Sep_ROTL16()`:

```c
a = a ^ c;
b = b ^ d;
c = c ^ b;
d = d ^ a;
...
X ^= ROTL16(X, 12) ^ ROTL16(X, 8);
```

That code does **not** implement the paper's intended rotation-based diffusion. Exhaustive simplification gives:

```text
Sep_ROTL16(a, b, c, d) = (b xor c, b, a, a xor d).
```

Consequences:

- output upper byte depends only on input upper byte
- output second nibble depends only on input second nibble
- lower-byte influence reaches the upper half only through carries introduced by the external modular additions

This is much closer to a triangular rotor machine than to a 16-bit SP-network.

## 2. Exact matched-context oracle

Let `P` be a chosen plaintext prefix and `C = Enc(IV, P)` the corresponding ciphertext prefix.

Because encryption and decryption in [`SEPAR/main.c`](C:/Users/noaho/Desktop/spear/SEPAR/main.c) use the **same** post-word state update, the internal state before processing the next word is identical in:

- encryption of `P || x`
- decryption of `C || y`

So for the next word we get an exact permutation pair:

```text
F_{P,IV}(x) = Enc(IV, P || x)[m]
G_{C,IV}(y) = Dec(IV, C || y)[m]
```

with

```text
G_{C,IV} = F_{P,IV}^{-1}.
```

This is the SEPAR analogue of the Hummingbird paper's "fixed internal handle" trick:

- we can return to the same internal state at will
- we can build the full `2^16` next-word codebook exactly
- we can peel guessed outer boxes offline with zero oracle noise

## 3. Weak-IV search

Because each stage only creates upper-byte branching through carries, some IVs make the exposed next-word permutation much more triangular than others.

For a fixed IV and empty prefix, define the simple row score:

```text
row_score(IV) =
  average over chosen input upper bytes h of
  | { upper_byte(Enc_IV(h || l)) : l in 0..255 } |.
```

Random-ish IVs give much larger row counts. Some IVs collapse dramatically.

On the default built-in key in the DLL, one good IV found by random search is:

```text
4703 EAC6 1B44 2157 747A 61DD A8FD DDD3
```

For that IV, the exposed one-word permutation is weak enough that the last stage key separates by a huge margin.

## 4. Exact outer-stage peel

For a fixed matched context and a candidate last segment key `K`, define

```text
T_K(x) = DEC_Block_8(F(x); K).
```

If `K = K8` is correct, then

```text
T_K(x) = R_7(x) + s8
```

where `R_7` is the reduced seven-stage cascade and `s8` is the hidden last-stage translation word.

The translation cancels from additive differentials:

```text
T_K(x + a) - T_K(x) = R_7(x + a) - R_7(x).
```

So an exact offline score is:

```text
score(K) = sum_a max_b |{ x : T_K(x + a) - T_K(x) = b }|.
```

Using the input-difference set

```text
{0001, 0002, 0004, 0008, 000F, 0010}
```

the true `K8` is dramatically separated on a weak IV.

On the default key and the weak IV above, the true `K8 = (FC7D, 6371)` scored:

```text
3468
```

while sampled wrong keys were clustered around roughly:

```text
1760..1830
```

This is a very large gap for an exact, noise-free offline distinguisher.

## 5. Recovering the hidden low byte of `state_8`

After peeling the correct `K8`, the low byte of the hidden translation word `s8` can be recovered by minimizing upper-byte branching:

```text
lo_score(t) = row_score( T_{K8}(x) - t ).
```

Only the low byte matters for the carry threshold, so this recovers `s8_low` directly.

On the same weak IV, the correct low byte is recovered exactly:

```text
s8_low = 0x69
```

## 6. Strip both ends and recurse

The key observation for the recursive step is that once we know:

- `K8`
- `s8_low`
- `K1`
- `s1`

we can strip the outer boxes on **both** sides and expose a middle permutation

```text
M( ENC_Block_1(x + s1; K1) ) = DEC_Block_8(F(x); K8) - s8_low.
```

This middle permutation is still SEPAR-shaped, but now its outer visible stage is `K7`.

Empirically, this drastically improves the next-stage score. On the default key:

- with the true `s1` and only `s8_low`, the true `K7` becomes the top-scoring sampled candidate on the stripped middle permutation
- full `s8` is not needed at this step

So the practical recursive picture is:

1. find a weak IV/context
2. recover `K8`
3. recover `s8_low`
4. strip the right side
5. recover the left-side gauge clean enough to strip the left side
6. score `K7` on the middle permutation
7. recurse

This is exactly the same divide-and-conquer spirit as the Hummingbird-1 attack:

- chosen context pins the state
- a small-word permutation is exposed exactly
- the outer keyed box is peeled
- the reduced inner machine is attacked next

## 7. Inverse-side outer peel: `K1`

The inverse oracle gives the left outer stage too.

Write the matched-context inverse permutation as

```text
G(y) = F^{-1}(y) = B1^{-1} o B2^{-1} o ... o B8^{-1}(y)
```

with

```text
B1(x) = ENC_Block_1(x + s1; K1)
B1^{-1}(u) = DEC_Block_1(u; K1) - s1.
```

If `K = K1` and `s = s1`, then

```text
U_{K,s}(y) = ENC_Block_1(G(y) + s; K)
```

peels the left outer box exactly and yields the reduced inverse cascade.

That gives a direct inverse-side score for `K1`.

One concrete decryption-weak IV is:

```text
E1A7 3BD3 03D5 2E68 11E1 2AF9 3264 B592
```

and under that IV, with the true `s1 = BF07`, the script recovers:

```text
K1 = (E8B9, B733)
```

with score:

```text
2142
```

while example wrong candidates score:

```text
1630, 1625, ...
```

The low byte of `s1` is also recoverable by a branching-minimization score on the inverse side.

## 8. Two-sided peel exposes `K7`

Once both outer boxes are known, we can build the exact middle permutation:

```text
M( ENC_Block_1(x + s1; K1) ) = DEC_Block_8(F(x); K8) - s8
```

or, in practice, already a very useful approximation using only `s8_low`.

This exposes stage 7 as the new right outer keyed box of the reduced machine.

Empirically:

- without peeling, `K7` is not cleanly identifiable
- after peeling `K1` and `K8`, the true `K7` jumps close to the top
- on some contexts it becomes the top candidate in small candidate sets
- over multiple contexts it remains consistently high while false keys fluctuate

This is the same phenomenon as in the Hummingbird paper: knowing the outer stages causes the inner-stage scores to jump.

## 9. One more right-side peel exposes `K6`

With the exact right-side state word `s7`, we can peel stage 7 as well:

```text
R6(x) = DEC_Block_7(M(x); K7) - s7.
```

Now stage 6 is the right outer stage of the reduced machine.

This step is already extremely strong in some chosen-IV contexts.

For example, with:

```text
IV = 22F1 FB5A 75AD 6F69 1212 3B70 9B1E 2E20
s1 = A3D4
s7 = C047
s8 = A2FA
```

the reduced table has:

```text
row(R6) = 11.33
```

and the true

```text
K6 = (F44A, 233E)
```

scores:

```text
10243
```

while example wrong candidates score only about:

```text
4782, 4753, ...
```

That is a huge separation and is already a bona fide multi-stage recursive break.

## 10. Symmetric visibility ladder

Using the exact peel machinery on the implementation key, the visible-stage ladder is now:

```text
original next-word permutation:          B8 o B7 o B6 o B5 o B4 o B3 o B2 o B1
after peeling K1 and K8:                 B7 o B6 o B5 o B4 o B3 o B2
after peeling K1, K7, K8:               B6 o B5 o B4 o B3 o B2
after peeling K1, K2, K6, K7, K8:       B5 o B4 o B3
after peeling K1, K2, K5, K6, K7, K8:   B4 o B3
```

And the stages that become directly scoreable are:

- after peeling `K1` and `K8`: `K2` on the left and `K7` on the right
- after peeling `K1`, `K7`, and `K8`: `K2` on the left and `K6` on the right
- after peeling `K1`, `K2`, `K6`, `K7`, and `K8`: `K3` on the left and `K5` on the right
- after peeling `K1`, `K2`, `K5`, `K6`, `K7`, and `K8`: `K3` on the left and `K4` on the right

Concrete exact scans:

1. With

```text
IV = 22F1 FB5A 75AD 6F69 1212 3B70 9B1E 2E20
```

after exact peels `{K1, K8}`:

- `K2 = (DA5D, 96D7)` scores `3452`, next sampled wrong `2810`
- `K7 = (8D1E, 9DF5)` scores `4783`, next sampled wrong `2575`

2. With

```text
IV = E1A7 3BD3 03D5 2E68 11E1 2AF9 3264 B592
```

after exact peels `{K1, K7, K8}`:

- `K2 = (DA5D, 96D7)` scores `7916`, next sampled wrong `3980`
- `K6 = (F44A, 233E)` scores `4594`, next sampled wrong `4089`

3. With

```text
IV = 4703 EAC6 1B44 2157 747A 61DD A8FD DDD3
```

after exact peels `{K1, K2, K6, K7, K8}`:

- `K3 = (02DD, 3972)` scores `11663`, next sampled wrong `5978`
- `K5 = (50C5, 12DB)` scores `6627`, next sampled wrong `5946`

4. On the same IV, after exact peels `{K1, K2, K5, K6, K7, K8}`:

- `K3 = (02DD, 3972)` scores `13376`, next sampled wrong `6678`
- `K4 = (E953, 07FD)` scores `13433`, next sampled wrong `6789`

So yes: the recursion is symmetric.

`K2` becomes visible immediately under the right contexts, `K3` becomes visible after one more symmetric peel, and even `K4` becomes directly exposed once the remaining outer-middle layer is removed.

## 11. What is already practical

The following parts are fully implemented and validated in
[`Attacks/full_key_recovery/hb1_style_stage_peel.py`](C:/Users/noaho/Desktop/spear/Attacks/full_key_recovery/hb1_style_stage_peel.py):

- chosen-IV weak-context search
- chosen-IV weak-context search on the inverse side
- joint weak-IV search for contexts weak in both directions
- exact matched-context forward and inverse codebook construction
- exact `K8` differential scoring
- exact `K1` differential scoring when `s1` is supplied
- `s8_low` recovery
- middle-permutation construction utilities for recursive exploration
- reduced-cascade `K7` / `K6` demo modes
- the companion scanner
  [`scan_stage_visibility.py`](C:/Users/noaho/Desktop/spear/Attacks/full_key_recovery/scan_stage_visibility.py)
  for exact or sampled visibility scans after arbitrary exact left/right peels

## 12. What is still annoying

The remaining automation problem is not the existence of the recursion. It is the gauge bookkeeping:

- the right-side high byte is invisible to the simple row score
- the left-side state word must be aligned well enough to expose the next outer stage sharply

Those are engineering problems, not evidence against the break.

At this point the implementation is already clearly broken in the Hummingbird sense:

- the outer segment key is recovered quickly and exactly
- the state machine exposes reproducible chosen-state 16-bit permutations
- the reduced middle machine remains weak after peeling

## 13. Sumarry

The implementation bug in `Sep_ROTL16()` is the devastating error.

It collapses each nominal 16-bit block into a triangular keyed permutation, and the matched-context oracle then turns the whole cipher into a sequence of peelable 16-bit boxes with tiny branching.

This is the same cryptanalytic pattern as the Hummingbird-1 break:

- small word size
- chosen-IV / chosen-context leverage
- outer-box peeling
- recursion on a reduced inner machine

SEPAR's implementation is structurally broken.
