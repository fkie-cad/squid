#!/bin/bash
set -e

export PATH="/riscv/bin:$PATH"
pacman -Sy --noconfirm autoconf automake make libtool gcc perl-file-fcntllock
mkdir -p dist/lib dist/include

# Build berkeley db
cd libdb/build_unix
CC="riscv64-unknown-linux-gnu-gcc" CFLAGS="-O0 -g -fno-jump-tables -mno-relax -D__thread=" ../dist/configure --prefix="$PWD/../../dist" --host=riscv64-unknown-linux-gnu --with-sysroot=/riscv/sysroot
make
cp db.h ../../dist/include/
cp .libs/libdb-5.3.so ../../dist/lib/libdb-5.3.so

# Build pcre2
cd ../../libpcre2
autoreconf -fi
CC="riscv64-unknown-linux-gnu-gcc" CFLAGS="-O0 -g -fno-jump-tables -mno-relax -D__thread=" ./configure --prefix="$PWD/../dist"  --host=riscv64-unknown-linux-gnu --with-sysroot=/riscv/sysroot --disable-jit --enable-utf --disable-cpp
make
cp ./.libs/libpcre2-8.so ../dist/lib/libpcre2-8.so.0
cp ./src/pcre2.h ../dist/include/

# Build Exim
cd ../Exim
mkdir -p src/Local
cp ../Makefile src/Local/
export EXIM_RELEASE_VERSION=4.98
make -C src
cp src/build-Linux-x86_64/exim ../dist/
