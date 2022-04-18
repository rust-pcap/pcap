# Contributing

## Code coverage

The current code coverage for the `main` branch is automatically published on every push to `main` on https://rust-pcap.github.io/pcap/.

### Pre-requisites

To obtain code coverage locally you will need the nightly compiler toolchain, [compatible LLVM coverage tools](https://doc.rust-lang.org/rustc/instrument-coverage.html#installing-llvm-coverage-tools), and [`grcov`](https://github.com/mozilla/grcov).

Make sure you have the nightly toolchain installed with `rustup`:
```
rustup install nightly
```

The easiest way to obtain compatible LLVM coverage tools is by adding the `llvm-tools-preview` `rustup` component (for nightly!):
```
rustup +nightly component add llvm-tools-preview
```

`grcov` can be installed through cargo:
```
cargo install grcov
```

### Obtaining code coverage

First, switch to the nightly toolchain. Note that switching toolchains is necessary, as opposed to just using the `+nightly` option, because `grcov` does not have such an option and will not be able to find (or worse, will find the incorrect version of) `llvm-tools-preview`.
```
rustup default nightly
```

Clean any previously compiled objects and binaries.
```
cargo clean
```

Compile and run the tests. We set `RUSTFLAGS="-C instrument-coverage"` to enable source-based code coverage and `LLVM_PROFILE_FILE="target/debug/coverage/profraw/pcap-%p-%m.profraw"` to make sure each test gets its own profile information.
```
RUSTFLAGS="-C instrument-coverage" LLVM_PROFILE_FILE="target/debug/profraw/pcap-%p-%m.profraw" cargo test --all-features
```

And finally, run `grcov` to obtain a report.
```
grcov target/debug/profraw -s src/ --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/coverage/
```

The code coverage report will be available in `target/debug/coverage/index.html` which you can explore in your browser.
```
xdg-open target/debug/coverage/index.html
```

### More information

For more information on LLVM code coverage in Rust: https://doc.rust-lang.org/rustc/instrument-coverage.html

For more information on `grcov`: https://github.com/mozilla/grcov
