# vso-scan

Async TCP connect scanner in Rust.

    cargo build --release
    ./target/release/vso-scan -t example.com -p 22,80,443,8000-8100 --banner --json

Flags: `-t` target, `-p` ports, `-c` concurrency (1-1000), `--tmo` ms (100-10000), `--banner`, `--json`.

Only scan hosts you own or have written permission to test.
