#!/usr/bin/env bash
if [[ $1 == install ]]; then
    # https://crates.io/crates/cargo-udeps
    # cargo install cargo-udeps --locked
    cargo install --git https://github.com/est31/cargo-udeps --locked
else
    cargo +nightly -Z unstable-options udeps "$@" 
fi
