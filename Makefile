CC = gcc
CFLAGS = -O3 -std=c11
.PHONY: check paper benchmark

separ_attack.exe: poc/main.c poc/acquire.c poc/recover.c $(wildcard poc/*.h) reference/separ.c
	$(CC) $(CFLAGS) -I. poc/main.c -o $@ -lbcrypt

check: tests/verify.exe tests/events.exe
	./tests/verify.exe
	./tests/events.exe
	python tests/bounds.py

tests/verify.exe: tests/verify.c $(wildcard poc/*.h) reference/separ.c
	$(CC) $(CFLAGS) -I. tests/verify.c -o $@

tests/events.exe: tests/events.c $(wildcard poc/*.h) reference/separ.c
	$(CC) $(CFLAGS) -I. tests/events.c -o $@

benchmark: separ_attack.exe
	python tests/benchmark.py

paper:
	cd paper && pdflatex -interaction=nonstopmode -halt-on-error main.tex
	cd paper && pdflatex -interaction=nonstopmode -halt-on-error main.tex

