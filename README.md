# pcap

This is a **Rust language** crate for accessing the packet sniffing capabilities of libpcap (or Npcap on Windows). If you need anything, feel free to post an issue or submit a pull request!

[![Linux](https://github.com/rust-pcap/pcap/actions/workflows/00-linux.yml/badge.svg)](https://github.com/rust-pcap/pcap/actions/workflows/00-linux.yml)
[![Mac OS](https://github.com/rust-pcap/pcap/actions/workflows/00-macos.yml/badge.svg)](https://github.com/rust-pcap/pcap/actions/workflows/00-macos.yml)
[![Windows](https://github.com/rust-pcap/pcap/actions/workflows/00-windows.yml/badge.svg)](https://github.com/rust-pcap/pcap/actions/workflows/00-windows.yml)
[![Coverage](https://rust-pcap.github.io/pcap/badges/flat.svg)](https://rust-pcap.github.io/pcap/index.html)
[![Crates.io](https://img.shields.io/crates/v/pcap.svg)](https://crates.io/crates/pcap)
[![Docs.rs](https://docs.rs/pcap/badge.svg)](https://docs.rs/pcap)

## Features:

* List devices
* Open capture handle on a device or savefiles
* Get packets from the capture handle
* Filter packets using BPF programs
* List/set/get datalink link types
* Configure some parameters like promiscuity and buffer length
* Write packets to savefiles
* Inject packets into an interface

See [examples](examples) for usage.

# Building

This crate requires the libpcap (or Npcap on Windows) library.

## Installing dependencies

### Windows

Install [Npcap](https://npcap.com/#download).

### Linux

Install the libraries and header files for the libpcap library. For example:

- On Debian based Linux: install `libpcap-dev`.
- On Fedora Linux: install `libpcap-devel`.

**Note:** If not running as root, you need to set capabilities like so: `sudo setcap cap_net_raw,cap_net_admin=eip path/to/bin`.

### Mac OS X

`libpcap` should be installed on Mac OS X by default.

**Note:** A timeout of zero may cause ```pcap::Capture::next``` to hang and never return (because it waits for the timeout to expire before returning). This can be fixed by using a non-zero timeout (as the libpcap manual recommends) and calling ```pcap::Capture::next``` in a loop.

## Linking

It is your responsibility, as the crate user, to configure linking with libpcap/wpcap to suit your needs (e.g. library version, static vs. dynamic linking, etc.) via your own [build script](https://doc.rust-lang.org/cargo/reference/build-scripts.html). For most setups, the defaults are most likely sufficient and you don't have to do anything special beyond installing libpcap as described above. The notes below are provided if the defaults are not suitable.

### Supporting different library versions

This crate supports several different versions of libpcap, such as wpcap, to ensure it can be compiled against older versions while still providing access to functionality available in newer versions. The build script will try to automatically detect the right version and configure pcap, but it may fail at this task. Especially, if you have an unusual build setup. If you are getting compilation error of the form
``` text
cannot find function `pcap_<some_function>` in module `raw`
```
then that is probably what is happening. It is likely that your libpcap does not support the newest libpcap API and pcap failed to query libpcap to find out which unsupported features it should exclude.

To solve this, you can try helping the pcap crate compile the correct feature set that is compatible with your libpcap using the following two approaches:

#### Library Location

When linking dynamically, pcap's build script queries libpcap for its version. It does not see search paths added with `cargo:rustc-link-search=native` by another build script, and for a library in an unconventional location it may detect the version of another libpcap or assume the newest API. Setting the `LIBPCAP_LIBDIR` environment variable to the library's directory avoids this.

If `LIBPCAP_LIBDIR` is unset, the build will attempt to find the library via `pkg-config` instead. On most setups, this is the easiest way to get things working and may even eliminate the need for any custom build scripts in your software.

**These options do not apply on Windows.** No library is linked at build time, and `LIBPCAP_LIBDIR` is ignored.

#### Library Version

If setting the library location does not help, or the library is linked statically, set the libpcap version manually with the `LIBPCAP_VER` environment variable (e.g., `env LIBPCAP_VER=1.5.0`). This should be necessary only for an old version of libpcap: when pcap cannot query libpcap for its API version, it warns and assumes the newest API.

Without pkg-config, or with `LIBPCAP_LIBDIR` set, pcap loads the library to query its version. That fails for a static library, for a library built for another target, and for any library on musl when the build script itself is linked statically, which rustup's musl toolchains do by default. In that case the version is taken from `pkgconfig/libpcap.pc` under `LIBPCAP_LIBDIR`, and without that file the newest API is assumed.

Note that `LIBPCAP_VER` is respected even if you haven't set `LIBPCAP_LIBDIR` and are using `pkg-config`. If it is unset, we'll find whatever available version as long as it's supported by the library.

On Windows there is no version to query. Each entrypoint is declared and resolved the first time it is called, so `LIBPCAP_VER` is required only when you deliberately wish to build against a reduced API. Calling an entrypoint that the installed `wpcap.dll` does not export, will return `Error::EntrypointNotFound` instead of failing the build.

## Optional Features

### `capture-stream`

Use the `capture-stream` feature to enable support for streamed packet captures.

```toml
[dependencies]
pcap = { version = "2", features = ["capture-stream"] }
```

## Unstable Features

Use at your own risk, we do not consider this our public API yet.

### `lending-iter`

Use the `lending-iter` feature to enable the lending packet iterator. See `lendingiterprint` example.

## Minimum Supported Rust Version (MSRV)

This crate uses Rust 2024 and requires a compiler version >= 1.85.

The feature `capture-stream` depends on `tokio = "1.0"`. Therefore, when `capture-stream` is enabled, this crate requires a compiler version new enough to compile the `tokio` crate.

Some dependencies no longer support our chosen MSRV. Since many crates do not consider this a breaking change there is not much that can be done to prevent this through semver requirements. However, users can protect themselves against such incompatibility with `Cargo.lock` file. We provide [`msrv.lock`](msrv.lock) which is the lockfile against which we test MSRV builds in our CI.

[Discuss the MSRV](https://github.com/rust-pcap/pcap/discussions/240).

# Documentation labels

Generating documentation with `cfg` labels requires a nightly toolchain.  To
use this feature set the environment variables:

```
RUSTFLAGS="--cfg docsrs"
RUSTDOCFLAGS="--cfg docsrs"
```

Then generate the documentation using `cargo +nightly doc --all-features`.

# License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

# Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
