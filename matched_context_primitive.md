# Matched-Context Forward/Inverse Oracle Primitive in SEPAR

## Statement

Let `P = (p_0, ..., p_{m-1})` be any chosen plaintext prefix, and let

```text
C = Enc(IV, P) = (c_0, ..., c_{m-1})
```

be its ciphertext prefix under the same key and IV.

Then the internal state immediately before processing the next word is identical in:

- encryption of `P || x`
- decryption of `C || y`

for arbitrary next words `x` and `y`.

Therefore the next word maps induced by that prefix form a matched permutation pair:

```text
F_{P,IV}(x) = Enc(IV, P || x)[m]
G_{C,IV}(y) = Dec(IV, C || y)[m]
```

with

```text
G_{C,IV} = F_{P,IV}^{-1}.
```

This gives the attacker a chosen context oracle and the exact inverse oracle on
the same 16-bit permutation

## Why this is true in the implementation

The key implementation fact is that encryption and decryption use the same state-update
rule after each processed word.

In encryption, the current word is processed through the cascade

```text
v12 = ENC_Block(pt + state_1, K1)
v23 = ENC_Block(v12 + state_2, K2)
...
v78 = ENC_Block(v67 + state_7, K7)
ct  = ENC_Block(v78 + state_8, K8)
```

and then the state is updated from the tuple `(v12, ..., v78)`; see main.c

In decryption, the current word is inverted through

```text
v78 = DEC_Block(ct,  K8) - state_8
v67 = DEC_Block(v78, K7) - state_7
...
v12 = DEC_Block(v23, K2) - state_2
pt  = DEC_Block(v12, K1) - state_1
```

and then the state is updated by the same formulas, using the same intermediate tuple
`(v12, ..., v78)`


## Proof frameowkr

Fix a key and IV.

Define the per word encryption transition as

```text
(ct, S') = E_word(S, pt)
```

and the per word decryption transition as

```text
(pt, S') = D_word(S, ct).
```

Because the decryption path exactly inverts the cascade, if `ct = E_word(S, pt).out`,
then `D_word(S, ct)` recovers the same `pt` and the same intermediate values `(v12, ..., v78)`.

Since the post word state update depends only on the pre word state and those
intermediate values, both directions produce the same next state `S'`.

Applying this one word argument inductively along a prefix shows:

- encryption of `P` reaches some state `S_m`
- decryption of `C = Enc(IV, P)` reaches the same state `S_m`

Hence the next word maps under these two prefixes are exact inverses of one another 


##impact


For every reachable prefix context, the attacker can:

- lock the cipher to a specific internal state handle via `(P, C)`
- evaluate the exact forward next-word permutation `F_{P,IV}`
- evaluate the exact inverse next-word permutation `F_{P,IV}^{-1}`
- build the full `2^16` codebook of that permutation with `2^16` oracle calls

This has several consequences.


The pair `(P, C)` identifies a reproducible internal state before the next word.
The attacker can return to that state at will by reusing the same prefix.

The word oriented cipher becomes a chosen state 16 bit permutation oracle
At any chosen position, SEPAR exposes a stateless 16-bit permutation and its inverse.

Andddd....... outer stages can be peeled offline!!

For a fixed matched context, write the next-word permutation as

```text
F = B8 o B7 o ... o B1,
B_i(x) = ENC_Block_i(x + s_i).
```

Then for any guessed outer key `K8`, the attacker can compute offline

```text
T_{K8}(x) = DEC_Block_8(F(x); K8).
```

If `K8` is correct, then

```text
T_{K8}(x) = R_7(x) + s_8
```

for the exact reduced 7-stage cascade `R_7`.


