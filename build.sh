#!/bin/bash

CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
cargo build --release --target aarch64-unknown-linux-gnu

if [ ! -d "dist" ]; then
    mkdir -p dist
fi

if [ ! -d "dist/aarch64-unknown-linux-gnu" ]; then
    mkdir -p dist/aarch64-unknown-linux-gnu
fi

cp  ./target/aarch64-unknown-linux-gnu/release/cima-sync-cli ./dist/aarch64-unknown-linux-gnu/