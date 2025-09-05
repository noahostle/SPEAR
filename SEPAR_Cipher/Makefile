# Project: humm_size (shared library version)

CC       = gcc.exe -D__DEBUG__
OBJ      = main.o
LIBS     = -L"C:/Program Files (x86)/Dev-Cpp/MinGW64/lib" -L"C:/Program Files (x86)/Dev-Cpp/MinGW64/x86_64-w64-mingw32/lib" -static-libgcc -g3
INCS     = -I"C:/Program Files (x86)/Dev-Cpp/MinGW64/include" -I"C:/Program Files (x86)/Dev-Cpp/MinGW64/x86_64-w64-mingw32/include"

BIN      = SEPAR.so
CFLAGS   = $(INCS) -g3 -fPIC    # fPIC needed for shared libraries
RM       = rm.exe -f

.PHONY: all clean

all: $(BIN)

clean:
	$(RM) $(OBJ) $(BIN)

# Compile the object file with -fPIC
main.o: main.c
	$(CC) -c main.c -o main.o $(CFLAGS)

# Link as a shared library
$(BIN): $(OBJ)
	$(CC) -shared $(OBJ) -o $(BIN) $(LIBS)

