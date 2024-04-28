# MUSL

This example shows how to compile [musl libc](https://musl.libc.org/) with the squid-toolchain.
This library shall be used as a replacement for the glibc because it not just contains less code
but the code is also less complex and easier to handle for `squid`.

## Download the source
```
git submodule update --init ./musl
cd musl
git apply ../musl-patch
cd ..
```

## Compile the code
Enter the `squid-toolchain` container:
```
docker run -it -v "$PWD:/io" squid-toolchain
```

Inside the container execute:
```
pacman -S make
cd /io
bash build.sh
```

## Get the library
The resulting library is available at `musl/lib/libc.so`.    
Rename it to `libc.so.6` to use it as a dependency of a RISC-V executable.

