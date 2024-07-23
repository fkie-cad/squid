# README demo

This folder holds the full code for the demo in the [README](../../README.md#demo).
To run the demo yourself you must first build the test program and then compile the harness.

## Building the target
Enter the `squid-toolchain` container
```
docker run -it --rm -v $PWD:/io squid-toolchain
```
Inside the container execute
```
cd /io
/riscv/bin/riscv64-unknown-linux-gnu-gcc -o test -fPIE -pie -O0 -g -fno-jump-tables -mno-relax -D__thread= test.c
```

Also, you need a `libc.so.6`, preferably [musl](../musl).

## Running the demo
Execute
```
LIBRARY_PATH="/path/to/libc/" cargo run --example readme-demo --release -- ./test <INDEX>
```

