#!/usr/bin/env sh
set -eu

threads=${SEPAR_TEST_THREADS:-4}
outer=./separ_prefix_attack
inward=./separ_ranked_inward

outer_self=$($outer --self-test)
printf '%s\n' "$outer_self"
printf '%s\n' "$outer_self" |
    grep -q '^\[self-test\] completing injectivity check ... ok$'

inward_self=$($inward --self-test --threads "$threads")
printf '%s\n' "$inward_self"
printf '%s\n' "$inward_self" |
    grep -q '^\[self-test\] serial/threaded joint-state order equivalence ... ok$'
printf '%s\n' "$inward_self" |
    grep -q '^\[self-test\] pivot induction, four carry bounds, and exact factor ... ok$'

outer_default=$($outer --threads "$threads" --top 1)
printf '%s\n' "$outer_default"
printf '%s\n' "$outer_default" |
    grep -q '^true_lane_rank=1 .* greater=0 '
printf '%s\n' "$outer_default" |
    grep -q '^candidate_K8=(FC7D,6371) score=1311$'
printf '%s\n' "$outer_default" |
    grep -q '^recovered_K8=(FC7D,6371) audit=match$'

# This reachable instance disproves universal S4-lane maximality.  The true
# lane is second; explicit score-ordered escalation nevertheless recovers K8.
witness_key=E327EAACDFC5765633A8CECCCBC7D7E0CD7A3ACFFA675B06E4E7004901112801
witness_iv=8D488D31DABD103BC78AB4351BCA28F7
witness=$($outer --threads "$threads" --key "$witness_key" --iv "$witness_iv" \
    --lane-rank 2 --top 1)
printf '%s\n' "$witness"
printf '%s\n' "$witness" | grep -q '^true_lane_rank=2 '
printf '%s\n' "$witness" |
    grep -q '^candidate_K8=(0111,2801) score=1306$'
printf '%s\n' "$witness" |
    grep -q '^recovered_K8=(0111,2801) audit=match$'

# A retained S4 fibre must be partitioned into one fast candidate plus every
# remaining raw pair, without duplicates or omissions.
fallback_counts=$($outer --threads "$threads" --top 1 --emit-fallback |
    awk '
        /^(candidate_K8|fallback_K8)=/ {
            pair = $0
            sub(/^[^(]*\(/, "", pair)
            sub(/\).*/, "", pair)
            gsub(/,/, "", pair)
            seen[pair] = 1
            if ($0 ~ /^candidate_K8=/) fast++
            else fallback++
        }
        END {
            for (pair in seen) unique++
            printf "%d %d %d\n", fast, fallback, unique
        }
    ')
test "$fallback_counts" = '1 110591 110592'

inward_default=$($inward --known-k8 FC7D6371 --threads "$threads" --contexts 8)
printf '%s\n' "$inward_default"
printf '%s\n' "$inward_default" |
    grep -q '^VERIFICATION=PASS codebooks=8x65536 held_out=2x64 '
printf '%s\n' "$inward_default" |
    grep -q '^RECOVERED_KEY=E8B9B733DA5D96D702DD3972E95307FD50C512DBF44A233E8D1E9DF5FC7D6371$'
printf '%s\n' "$inward_default" | grep -q '^RESULT=SUCCESS '

if [ "${SEPAR_HARD_TEST:-0}" = 1 ]; then
    hard=$($inward \
        --oracle-key C6D1F1362A9CB82B990AF96484C10BD99D6C6A679E0682372AF32DC1A2B55AA1 \
        --known-k8 A2B55AA1 --threads "$threads" --contexts 8 \
        --state-tiers 1 --audit)
    printf '%s\n' "$hard"
    printf '%s\n' "$hard" |
        grep -q '^CONTEXT_RETIRED stage=6 context=6 first_tier=256 '
    printf '%s\n' "$hard" |
        grep -q '^VERIFICATION=PASS codebooks=8x65536 held_out=2x64 reconstructed_initialization_contexts=7 retired_contexts=1$'
    printf '%s\n' "$hard" |
        grep -q '^RECOVERED_KEY=C6D1F1362A9CB82B990AF96484C10BD99D6C6A679E0682372AF32DC1A2B55AA1$'
    printf '%s\n' "$hard" | grep -q '^AUDIT_EXACT_KEY=PASS$'
fi

echo '[test] cipher, outer bootstrap, exhaustive fallback, and inward recovery passed'
