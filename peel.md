peel attack scratch

what this is actually trying to recover

- separ master key = 16 x 16-bit words = 8 x 32-bit stage keypairs
- stage 1 keypair = key[0], key[1]
- stage 2 keypair = key[2], key[3]
- ...
- stage 8 keypair = key[14], key[15]
- so if i recover all 8 stage keypairs, that is exact 256-bit master key recovery, not just an equivalent key
- for a fixed chosen iv, i also need the 8 initialized 16-bit state words to peel the cascade cleanly
- if i recover both the 8 keypairs and the 8 initialized states for one iv, i can clone the whole stream for that iv because the state update is public
- if i recover the 8 keypairs only, i still win completely because i can recompute the states for any iv

core idea

- build first-block codebook T(p) = E_k,iv(p) for all 2^16 plaintext words under one chosen iv
- this costs 65536 online encryptions and no decryption oracle
- exploit the fact that enc_block / dec_block high byte depends only on input high byte
- stronger version: output nibble 1 depends only on input nibble 1
- for a candidate outer stage keypair, partially invert that stage on sampled codebook points and score how collapsed the residual high-byte support is
- the true stage keypair gives the smallest support
- once a stage keypair is fixed, partially decode that stage
- the missing state high byte can then be ranked by rescoring the 256 possible high-byte branches with one precomputed dec_block table from the next inner stage
- recurse inward

important limitation right now

- the keypair ranking is very strong on all 8 stages
- the state-high ranking is very strong from stage 7 inward, and still very small-beam on stage 8
- but the score output called best_low is not always the true state low byte
- so i do not yet have a push-button full 256-bit recovery script
- current status is: the recursion is real, but exact state-word recovery still needs one more step

exact objects being recovered / ranked in the current prototype

- stage keypairs for stages 8 down to 1
- initialized state high byte for stages 8 down to 2 via the next-stage branch score
- initialized state low byte sometimes exactly, sometimes only a near-by borrow-alignment value

true stage keypairs in the local validation key

- stage 1 = E8B9B733
- stage 2 = DA5D96D7
- stage 3 = 02DD3972
- stage 4 = E95307FD
- stage 5 = 50C512DB
- stage 6 = F44A233E
- stage 7 = 8D1E9DF5
- stage 8 = FC7D6371

key ranking outputs so far

params used here:
- demo-rank --random-candidates 80 --sample-highs 8 --low-step 8 --seed 0

stage 8
- true keypair FC7D6371
- true state low 18
- score line: score=109 low=18 true FC7D6371
- true rank = 1/81

stage 7
- true keypair 8D1E9DF5
- true state low 02
- top tied lines:
  score=108 low=01 rand 80424B3E
  score=108 low=FE rand A3DEFA83
  score=108 low=02 true 8D1E9DF5
- true rank = 3/81

stage 6
- true keypair F44A233E
- true state low 21
- score line: score=87 low=1E true F44A233E
- true rank = 1/81

stage 5
- true keypair 50C512DB
- true state low 23
- score line: score=65 low=22 true 50C512DB
- true rank = 1/81

stage 4
- true keypair E95307FD
- true state low 17
- score line: score=48 low=17 true E95307FD
- true rank = 1/81

stage 3
- true keypair 02DD3972
- true state low 69
- score line: score=25 low=5D true 02DD3972
- true rank = 1/81

stage 2
- true keypair DA5D96D7
- true state low CE
- score line: score=16 low=BE true DA5D96D7
- true rank = 1/81

stage 1
- true keypair E8B9B733
- true state low 40
- score line: score=8 low=39 true E8B9B733
- true rank = 1/81

state-high branch outputs so far

params used here:
- demo-state-high --sample-highs 8 --low-step 8

stage 8 via stage 7
- true state word = 2518
- true state high = 25
- minimum-score cluster included:
  score=108 next_low=01 state_high=77
  score=108 next_low=01 state_high=AA
  score=108 next_low=02 state_high=25
  score=108 next_low=02 state_high=E2
  score=108 next_low=03 state_high=10
  score=108 next_low=05 state_high=12
  score=108 next_low=FC state_high=A9
- true rank = 3/256
- so stage 8 high is not unique yet, but it is already a tiny tied beam, not a full 256-way uncertainty

stage 7 via stage 6
- true state word = 5C02
- best line: score=87 next_low=1E state_high=5C
- true rank = 1/256

stage 6 via stage 5
- true state word = 9E21
- best line: score=65 next_low=22 state_high=9E
- true rank = 1/256

stage 5 via stage 4
- true state word = 0823
- best line: score=48 next_low=17 state_high=08
- true rank = 1/256

stage 4 via stage 3
- true state word = 4117
- best line: score=25 next_low=5D state_high=41
- true rank = 1/256

stage 3 via stage 2
- true state word = 7069
- best line: score=16 next_low=BE state_high=70
- true rank = 1/256

stage 2 via stage 1
- true state word = FECE
- best line: score=8 next_low=39 state_high=FE
- true rank = 1/256

note on best_low vs true low

- exact matches:
  stage 8: true low 18, best_low 18
  stage 7: true low 02, best_low 02
  stage 4: true low 17, best_low 17
- near but not exact:
  stage 6: true low 21, best_low 1E
  stage 5: true low 23, best_low 22
  stage 3: true low 69, best_low 5D
  stage 2: true low CE, best_low BE
  stage 1: true low 40, best_low 39
- this is the main reason the attack is not fully automated yet

effort

online

- one chosen-iv first-block codebook = 65536 oracle encryptions = 2^16
- no decryption oracle needed
- if i want more than one iv to break ties, cost scales linearly
- 2 ivs = 131072 queries
- 4 ivs = 262144 queries

offline

- one sampled key score with current params costs:
  256 low guesses x 8 sampled plaintext-high groups x 32 sampled low-byte values
  = 65536 dec_block evaluations
  = 2^16 local block ops per candidate keypair
- one full state-high ranking with current params, once the next inner key is known, costs:
  256 state-high guesses x 256 next-low guesses x 8 x 32 sampled points
  = 16777216 table lookups / subtractions
  = about 2^24 cheap local ops

very important honesty note on offline cost

- the current code proves the score is extremely discriminating
- it does not yet do a full 2^32 exhaustive search over every stage keypair
- naive exhaustive search with the current score would be about 2^32 candidate keypairs x 2^16 score cost
- that is about 2^48 local block ops per stage, so too large as-is
- so the online cost is already good and concrete
- the remaining problem is reducing / guiding the offline stage-key search, not getting more oracle data

why this still feels like a real break path

- the same structural score works all the way from stage 8 down to stage 1
- the next-stage branch score resolves the missing state high byte uniquely from stage 7 inward
- even stage 8 only leaves a tiny tied beam
- the cipher is clearly decomposing stage by stage from one 2^16 codebook
- i am no longer stuck on "does recursion work"; it does
- i am stuck on "how do i turn the ranking signal into a complete exact recovery algorithm cheaply"

commands i used for the evidence above

```text
python stage_peel_attack.py demo-rank --stage 8 --random-candidates 80 --sample-highs 8 --low-step 8 --seed 0
python stage_peel_attack.py demo-rank --stage 7 --random-candidates 80 --sample-highs 8 --low-step 8 --seed 0
python stage_peel_attack.py demo-rank --stage 6 --random-candidates 80 --sample-highs 8 --low-step 8 --seed 0
python stage_peel_attack.py demo-rank --stage 5 --random-candidates 80 --sample-highs 8 --low-step 8 --seed 0
python stage_peel_attack.py demo-rank --stage 4 --random-candidates 80 --sample-highs 8 --low-step 8 --seed 0
python stage_peel_attack.py demo-rank --stage 3 --random-candidates 80 --sample-highs 8 --low-step 8 --seed 0
python stage_peel_attack.py demo-rank --stage 2 --random-candidates 80 --sample-highs 8 --low-step 8 --seed 0
python stage_peel_attack.py demo-rank --stage 1 --random-candidates 80 --sample-highs 8 --low-step 8 --seed 0

python stage_peel_attack.py demo-state-high --stage 8 --sample-highs 8 --low-step 8 --top 10
python stage_peel_attack.py demo-state-high --stage 7 --sample-highs 8 --low-step 8 --top 10
python stage_peel_attack.py demo-state-high --stage 6 --sample-highs 8 --low-step 8 --top 10
python stage_peel_attack.py demo-state-high --stage 5 --sample-highs 8 --low-step 8 --top 10
python stage_peel_attack.py demo-state-high --stage 4 --sample-highs 8 --low-step 8 --top 10
python stage_peel_attack.py demo-state-high --stage 3 --sample-highs 8 --low-step 8 --top 10
python stage_peel_attack.py demo-state-high --stage 2 --sample-highs 8 --low-step 8 --top 10
```

bottom line

- one 2^16 chosen-plaintext codebook under one iv seems enough to expose all 8 stage keypairs one by one
- current evidence says the cipher really is peeling apart stage-wise
- exact master-key recovery is not fully scripted yet, but this is now much closer to key recovery than to a plain codebook attack
