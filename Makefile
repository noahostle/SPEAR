CC = gcc
CFLAGS = -O3 -std=c11

separ_attack.exe: main.c poc/acquire.c poc/recover.c $(wildcard poc/*.h) reference/separ.c
	$(CC) $(CFLAGS) main.c -o $@ -lbcrypt