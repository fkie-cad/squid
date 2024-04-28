CC=/ewe/gcc
CFLAGS=-g -O0 -fvisibility=hidden -fPIC -shared -nostdlib -mno-relax

C_FILES=$(wildcard src/*.c)
H_FILES=$(wildcard src/*.h)
BINARIES=ld-linux-riscv64-lp64d.so.1 libdl.so.2

all: $(BINARIES)

$(BINARIES): $(C_FILES) $(H_FILES)
	$(CC) -o $@ $(CFLAGS) -Isrc/ $(C_FILES)

.PHONY: clean, all
clean:
	@rm -fv $(BINARIES) *.ewe
