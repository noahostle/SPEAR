stages appear to be seperable since each stage key can be scored due to bias in the diffusion, and the true keys consistently outperform the wrong keys.

this allows a 2^32 scan to be performed for each candidate, and those candidates can be ranked and the correct stage key can be consistently bruteforced.

this works for all stages, with stages 6 through 1 taking only a few hours on my machine, but stage 7 (being the first stage after the initial stage 8 scan) has too many candidates to be feasible (takes years on my machine)

as such i have constructed a demo that force includes the true key among a smaller (~4million) subset of random keys to test that the attack works without performing the full bruteforce, while i work on refining stage 7.

