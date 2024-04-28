# Fuzzing readelf with squid

This example shows how to build a readelf fuzzer with `squid` and LibAFL that combines
native and emulation-based fuzzing for maximum performance.

## Download the source
```
git submodule update --init ./binutils-gdb
cd binutils-gdb
git apply ../binutils.patch
cd ..
```

## Compile the source
Enter the `squid-toolchain` container:
```
docker run --rm -it -v "$PWD:/io" squid-toolchain
```

Inside the container execute:
```
pacman -Sy make texinfo bison diffutils gcc
cd /io
bash build.sh
```

This creates our fuzz target at `binutils-gdb/binutils/readelf`.

## Prepare the fuzzer
Create a folder called `binaries`, where we are gonna put the RISC-V binaries `readelf` and its dependencies `libdl.so.2` and `libc.so.6`.
`libdl.so.2` may come from [ant](../../ant) and `libc.so.6` may be the [musl libc](../musl).
```
mkdir binaries
cp binutils-gdb/binutils/readelf ./binaries
cp ../musl/musl/lib/libc.so ./binaries/libc.so.6
cp ../../ant/libdl.so.2 ./binaries
```

Then, we create a corpus:
```
mkdir corpus
echo -en "\x00" > corpus/0
```

Finally, we are gonna prepare a native `readelf` binary compiled with `afl-clang-lto` from the `binutil-gdb` source tree:
```sh
cd binutils-gdb
CC="$AFL_PATH/afl-clang-lto" CFLAGS="-flto -fomit-frame-pointer -Ofast" LDFLAGS="-flto" ./configure
make
```

## Run the fuzzer
We are gonna spawn two instances of the fuzzer. A speedy instance with the `afl-clang-lto` compiled binary and
a slow instance with `squid` and advanced crash oracles.

```
cargo run --release --example readelf_fuzzer -- fuzz \
    --riscv-binaries ./binaries \
    --corpus ./corpus \
    --output ./output \
    --cores 0-1 \
    --native-binary binutils-gdb/binutils/readelf
```

