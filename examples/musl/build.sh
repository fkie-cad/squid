#!/bin/bash
set -e

export PATH="$PATH:/riscv/bin/"

cd musl
CC=/riscv/bin/riscv64-unknown-linux-gnu-gcc CFLAGS="-g -O0 -fno-jump-tables -mno-relax" ./configure --host=riscv64-unknown-linux-gnu --with-sysroot=/riscv/sysroot --enable-debug --disable-static
make

