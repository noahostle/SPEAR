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

full=$($attack "$demo_key" | tr '\r' '\n')
printf '%s\n' "$full"
printf '%s\n' "$full" |
    grep -q '^K8 : FC7D6371$'
printf '%s\n' "$full" |
    grep -q '^K7 : 8D1E9DF5$'
printf '%s\n' "$full" |
    grep -q '^K6 : F44A233E$'
printf '%s\n' "$full" |
    grep -q '^K5 : 50C512DB$'
printf '%s\n' "$full" | grep -q '^K4 : E95307FD$'
printf '%s\n' "$full" | grep -q '^K3 : 02DD3972$'
printf '%s\n' "$full" | grep -q '^K2 : DA5D96D7$'
printf '%s\n' "$full" | grep -q '^K1 : E8B9B733$'
printf '%s\n' "$full" | grep -q '^Working: complete$'
printf '%s\n' "$full" |
    grep -q '^\[################################\] 100%$'
if printf '%s\n' "$full" |
    grep -Eq '^(SEPAR |MODE=|STAGE=|ORACLE |RESULT=|FULL_ATTACK_RESULT=)'; then
    echo '[test] debug output leaked into default mode' >&2
    exit 1
fi

echo '[test] unified outer-to-inward recovery passed'
