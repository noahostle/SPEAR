CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O3 -std=c11 -Wall -Wextra -Wpedantic -Werror
LDLIBS ?= -pthread

.PHONY: all test clean

all: separ_attack

separ_attack: separ_attack.c
	$(CC) $(CPPFLAGS) $(CFLAGS) separ_attack.c -o $@ $(LDLIBS)

test: all
	sh ./test.sh

clean:
	$(RM) separ_attack separ_prefix_attack separ_ranked_inward
