CC = gcc
CFLAGS = -O3 -std=c11 -Wall -Wextra -Werror -pedantic

separ_attack.exe: main.c poc/acquire.c poc/recover.c $(wildcard poc/*.h) reference/separ.c
	$(CC) $(CFLAGS) main.c -o $@ -lbcrypt
