# Ant

Ant is a fake dynamic linker DSO and replaces
- `ld-linux-riscv64-lp64d.so.1`
- `libdl.so.2`

At the moment `ant` does nothing but raise breakpoints in its functions
but that may change in the future.

## Building
Start the `squid-toolchain` container:
```
docker run --rm -it -v "$PWD:/io" squid-toolchain
```

Inside the container execute:
```
pacman -S make
cd /io
make
```

