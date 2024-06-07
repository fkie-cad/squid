# Running a hello world program with squid

This example showcases the bare minimum steps necessary to get `squid` up and running.

## Build the target
Enter the `squid-toolchain` container:
```
docker run --rm -it -v "$PWD:/io" squid-toolchain
```

And execute
```
pacman -S make
cd /io
make
```

## Run the emulator
Simply run
```
cargo run --example helloworld
```
