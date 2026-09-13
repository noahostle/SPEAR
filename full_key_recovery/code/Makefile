CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -Wpedantic -Werror
LDLIBS ?= -pthread

.PHONY: all test hard-test clean

all: separ_prefix_attack separ_ranked_inward

separ_prefix_attack: separ_prefix_attack.c separ_common.h
	$(CC) $(CPPFLAGS) $(CFLAGS) separ_prefix_attack.c -o $@ $(LDLIBS)

separ_ranked_inward: separ_ranked_inward.c separ_common.h
	$(CC) $(CPPFLAGS) $(CFLAGS) separ_ranked_inward.c -o $@ $(LDLIBS)

test: all
	sh ./test.sh

hard-test: all
	SEPAR_HARD_TEST=1 sh ./test.sh

clean:
	$(RM) separ_prefix_attack separ_ranked_inward
