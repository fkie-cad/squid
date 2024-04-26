FROM rust:latest AS ewe-builder
WORKDIR ewe
COPY ewe/Cargo.toml ./
COPY ewe/src/ ./src/
RUN cargo build --release --bins

FROM archlinux:latest AS toolchain-builder
ARG jobs="1"
RUN pacman-key --init && \
    pacman-key --populate && \
    pacman -Sy --noconfirm archlinux-keyring && \
    pacman -Su --noconfirm git autoconf automake curl python3 libmpc mpfr gmp gawk base-devel bison flex texinfo gperf libtool patchutils bc zlib expat
WORKDIR /riscv-gnu-toolchain
RUN git clone --progress https://github.com/pd-fkie/riscv-gnu-toolchain . && \
    git fetch --tags && \
    git checkout squid-version
RUN git submodule update --init --recursive --progress ./gcc && \
    git submodule update --init --recursive --progress ./glibc && \
    git submodule update --init --recursive --progress ./binutils && \
    git submodule update --init --recursive --progress ./gdb
RUN autoreconf -i && \
    mkdir -p /riscv && \
    ./configure --prefix=/riscv --with-arch=rv64iafdm --with-target-cflags="-fno-jump-tables -g" --with-target-cxxflags="-fno-jump-tables -g" && \
    make -j $jobs linux

FROM archlinux:latest AS squid
RUN mkdir -p /riscv && pacman -Sy --noconfirm glibc libisl libmpc flex python guile qemu-user
COPY --from=toolchain-builder /riscv /riscv/
COPY --from=ewe-builder /ewe /ewe/
ENTRYPOINT /bin/bash -i
