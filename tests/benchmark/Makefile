CC=/riscv/bin/riscv64-unknown-linux-gnu-gcc
CFLAGS=-Wall -Wextra -Wpedantic -Werror -fPIE -pie -O0 -g -fno-jump-tables -mno-relax -D__thread= -nostdlib -Wl,-emain -Wl,-dynamic-linker,/riscv/sysroot/lib/ld-2.33.so

bench: main.c
	$(CC) -o $@ $(CFLAGS) $^

.PHONY: clean
clean:
	@rm -fv bench
