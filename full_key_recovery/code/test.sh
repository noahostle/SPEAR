#!/usr/bin/env sh
set -eu

attack=./separ_attack
demo_key=E8B9B733DA5D96D702DD3972E95307FD50C512DBF44A233E8D1E9DF5FC7D6371

self_test=$($attack --self-test)
printf '%s\n' "$self_test"
printf '%s\n' "$self_test" |
    grep -q '^\[self-test\] completing injectivity check ... ok$'
printf '%s\n' "$self_test" |
    grep -q '^\[self-test\] serial/threaded joint-state order equivalence ... ok$'
printf '%s\n' "$self_test" |
    grep -q '^\[self-test\] pivot induction, four carry bounds, and exact factor ... ok$'

if $attack 00 >/dev/null 2>&1; then
    echo '[test] malformed key was accepted' >&2
    exit 1
fi

full=$($attack "$demo_key")
printf '%s\n' "$full"
printf '%s\n' "$full" |
    grep -q '^OUTER_SELECTED_K8=FC7D6371$'
printf '%s\n' "$full" |
    grep -q '^PHASE_HANDOFF K8=FC7D6371 source=outer-transcript-ranking$'
printf '%s\n' "$full" |
    grep -q '^VERIFICATION=PASS codebooks=8x65536 held_out=2x64 '
printf '%s\n' "$full" |
    grep -q '^RECOVERED_KEY=E8B9B733DA5D96D702DD3972E95307FD50C512DBF44A233E8D1E9DF5FC7D6371$'
printf '%s\n' "$full" | grep -q '^DEMO_EXACT=PASS$'
printf '%s\n' "$full" | grep -q '^FULL_ATTACK_RESULT=SUCCESS$'

echo '[test] unified outer-to-inward recovery passed'
