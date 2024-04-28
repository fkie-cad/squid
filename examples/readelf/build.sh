#!/bin/sh
set -e

export PATH="/riscv/bin/:$PATH"

cd binutils-gdb/zlib
CFLAGS="-O0 -g -fPIC -fno-jump-tables -mno-relax" ./configure --host=riscv64-unknown-linux-gnu --without-system-zlib --disable-shared
make

cd ../libsframe
CFLAGS="-O0 -g -fPIC -fno-jump-tables -mno-relax" ./configure --host=riscv64-unknown-linux-gnu --disable-shared
make

cd ../bfd
CFLAGS="-O0 -g -fPIC -fno-jump-tables -mno-relax" ./configure --host=riscv64-unknown-linux-gnu --disable-nls --without-zstd --without-system-zlib --disable-shared
make

cd ../libiberty
CFLAGS="-O0 -g -fPIC -fno-jump-tables -mno-relax" ./configure --host=riscv64-unknown-linux-gnu --disable-shared
make

cd ../opcodes/
CFLAGS="-O0 -g -fPIC -fno-jump-tables -mno-relax" ./configure --host=riscv64-unknown-linux-gnu --disable-shared
make

cd ../binutils
CFLAGS="-O0 -g -fPIE -fno-jump-tables -mno-relax" LDFLAGS="-pie" ./configure --host=riscv64-unknown-linux-gnu --disable-libctf --disable-nls --without-zstd --disable-shared --without-system-zlib
make readelf

