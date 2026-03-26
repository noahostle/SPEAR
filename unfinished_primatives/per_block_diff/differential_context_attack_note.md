# Differential Consistency Attack Note for `K8`

scan_enc_block_differntials.py
scans show that the implemented `ENC_Block` has extremely strong exact differential structure.

The strongest full-block XOR cells were around

```text
4682 / 65536 ≈ 2^-3.81,
```

with the best trails concentrated in the lowest nibble. That already proves the block
core is far from random.

The new point is that this differential weakness combines extremely well (for us not for the cipher) with the
matched context oracle thing.

From the matched context property, a chosen plaintext prefix `P` and its ciphertext
prefix `C = Enc(IV, P)` expose a full next-word permutation

```text
F(x) = Enc(IV, P || x)[m]
```

and its exact inverse

```text
F^{-1}(y) = Dec(IV, C || y)[m].
```

So for a fixed context we are not working with sparse differential samples. We can build
the full `2^16` codebook exactly.

That removes any + all statistical noise from the outer test.

## Outer-key peel and the right differential

For a candidate last-segment key `K`, define

```text
T_K(x) = DEC_Block_8(F(x); K).
```

If `K = K8` is the true last segment key, then

```text
T_K(x) = R_7(x) + s8
```

for the exact reduced 7-stage cascade `R_7` and the hidden last-stage offset `s8`.

At this point the correct differential notion is **additive**, not XOR:

```text
T_K(x + a) - T_K(x) = R_7(x + a) - R_7(x).
```

The hidden translation `s8` cancels precisely

So additive differential counts of `T_K` give a translation invariant fingerprint of the
peeled reduced cascade. Wrong key guesses do not preserve that structure in general and act like a random permutation, so
will have a mucher lower score.

## scoring

The implemented scanner uses the exact score

```text
score(K) = sum_a max_b |{ x : T_K(x + a) - T_K(x) = b }|,
```

over a chosen set of additive input differences, currently

```text
{0001, 0002, 0004, 0008, 000F, 0010}.
```

This score is:

- exact, because the whole 16-bit codebook is known
- translation invariant in the outer offset `s8`

On the matched context produced by prefix `0x2028`, the score gave:

- correct `K8 = (FC7D, 6371)`: `2292`
- wrong `(1111, 2222)`: `1735`
- wrong `(0000, 0000)`: `1438`
- wrong `(BEEF, 1234)`: `1428`
- wrong `(FC7D, 6370)`: `1419`

So the =score is significantly stronger for true keys than it is for wrong ones.

## Scripts

scan_enc_block_differentials.py
This script computes exact XOR and / or additive differential counts for the implemented
`ENC_Block` under a chosen segment key and stage. 

scan_context_k8_differentials.py:
1. builds the exact matched context next word codebook from the oracle
2. peels a candidate `K8` offline by applying `DEC_Block_8`
3. scores the peeled table by additive differential
4. ranks the key candidates



I think we can now use the single enc block in combination with the context matching to exactly differential guess a single outer
enc block, and then ??somehow?? recover `s8`, and then peel back to K7 using context matching.
