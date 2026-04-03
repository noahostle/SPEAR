# Autonomous Nibble Channel Attack Note

block core:

- one output nibble of `ENC_Block` is an autonomous 4-bit permutation lane
- the same is true for `DEC_Block`
- that lane is small enough to admit exact differential-sequence style fingerprints


For every 32-bit segment key `K = (k0, k1)` and every rotor index `n in {1, ..., 8}`,
the second nibble of the block output depends only on the second nibble of the block
input.

Equivalently, for both encryption and decryption there exists a keyed 4-bit permutation
such that

```text
ENC_Block_K,n(a || b || c || d)_nibble2 = f_K(b)
DEC_Block_K,n(a || b || c || d)_nibble2 = f_K^{-1}(b)
```

where the 16bit word is written in nibble order `(a, b, c, d)` from most significant to
least significant.

this lane ignores the other 12 input bits completely.

we already know

```text
L(a, b, c, d) = (b xor c, b, a, a xor d).
```

If the state before one S-box layer is `(u_r, v_r, w_r, z_r)` and the per-round key
nibbles are `(\alpha_r, \beta_r, \gamma_r, \delta_r)`, then the implemented recurrence
implies

```text
v_{r+1} = S2(v_r xor \beta_r)
```

independently of `u_r`, `w_r`, and `z_r`.

That means the second nibble evolves as its own 4-bit SPN, isolated from the rest of the
block.

Let

```text
\beta_0 = nibble_2(k0)
\beta_1 = nibble_2(k1)
\beta_2 = nibble_2(key2)
\beta_3 = nibble_2(key3)
```

for the stage-local derived words `key2` and `key3`.

Then the second output nibble is exactly

```text
v2 = S2(b xor \beta_0)
v3 = S2(v2 xor \beta_1)
v4 = S2(v3 xor \beta_2)
v5 = S2(v4 xor \beta_3)
f_K(b) = S2(v5 xor \beta_0 xor \beta_1) xor \beta_2 xor \beta_3
```

So the lane is an explicit 5-layer 4-bit keyed permutation using only `S2`.


furthermore

```text
(\beta_0, \beta_1, \beta_2, \beta_3)
```

determines the 4-bit permutation injectively.

In the current analysis, all `2^16 = 65536` abstract tuples gave distinct 4-bit
permutations.



The stage index `n` only modifies the low nibble of `key2` and `key3` through

```text
key2 ^= (n + 2)
key3 ^= (n + 3).
```

but that low nibble never enters the autonomous second-nibble lane.

so the lane permutation does not depend on the rotor number at all:

```text
f_{K,n} = f_K.
```

This makes the eight stage positions look identical at the lane level


## impact

instead of attacking a 16 bit SPN as a whole, the attacker gets a true 4-bit keyed
permutation channel inside the block. This is easier to fingerprint

For the xor differential

```text
\Delta_d(b) = f_K(b xor d) xor f_K(b),
```

the full lane differential sequence is highly key-specific:

- for every nonzero `d`, the support size of `\Delta_d` is at most `8`
- some lane keys even give constant outputs for some deltas
- using only `d = 1, 2`, the resulting signatures gave `65197` distinct cases out of
  `65536`, with maximum multiplicity `3`

So once the outer lane is exposed it is a very strong fingerprint for identifying key bytes

also, because the lane depends on only a 16-bit abstract subkey, any successful lane
fingerprint collapses the segment key search from `2^32` down to about `2^16` average
candidates immediately.

this allows you to filter down the candidate keys if scoring them takes many (2^n) operations


alsp, if an outer stage is peeled correctly, the reduced cipher still contains the same
lane structure in its new outer stage

- fingerprint outer stage
- peel stage
- expose the next outer lane
- repeat


