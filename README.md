# pcap [![Build status](https://api.travis-ci.org/ebfull/pcap.svg)](https://travis-ci.org/ebfull/pcap) [![Crates.io](https://img.shields.io/crates/v/pcap.svg)](https://crates.io/crates/pcap) [![Docs.rs](https://docs.rs/pcap/badge.svg)](https://docs.rs/pcap) #

### [Documentation](https://docs.rs/pcap)

This is a **Rust language** crate for accessing the packet sniffing capabilities of pcap (or wpcap on Windows).
If you need anything feel free to post an issue or submit a pull request!

## Features:

* List devices
* Open capture handle on a device or savefiles
* Get packets from the capture handle
* Filter packets using BPF programs
* List/set/get datalink link types
* Configure some parameters like promiscuity and buffer length
* Write packets to savefiles
* Inject packets into an interface

See examples for usage.

# Building

As of 0.8.0 this crate uses Rust 2018 and requires a compiler version >= 1.40.0.

As of 0.9.0 the `capture-stream` feature requires a compiler version >= 1.45.0.

## Windows

Install [WinPcap](http://www.winpcap.org/install/default.htm).

Download the WinPcap [Developer's Pack](https://www.winpcap.org/devel.htm).
Add the `/Lib` or `/Lib/x64` folder to your `LIB` environment variable.

## Linux

On Debian based Linux, install `libpcap-dev`. If not running as root, you need to set capabilities like so: ```sudo setcap cap_net_raw,cap_net_admin=eip path/to/bin```

## Mac OS X

libpcap should be installed on Mac OS X by default.

**Note:** A timeout of zero may cause ```pcap::Capture::next``` to hang and never return (because it waits for the timeout to expire before returning). This can be fixed by using a non-zero timeout (as the libpcap manual recommends) and calling ```pcap::Capture::next``` in a loop.

## Library Location

If `LIBPCAP_LIBDIR` environment variable is set when building the crate, it will be added to the linker search path - this allows linking against a specific `libpcap`.

## Library Version

The crate will automatically try to detect the installed `libpcap`/`wpcap` version by loading it during the build and calling `pcap_lib_version`. If for some reason this is not suitable, you can specify the desired library version by setting the environment variable `LIBPCAP_VER` to the desired version (e.g. `env LIBPCAP_VER=1.5.0`). The version number is used to determine which library calls to include in the compilation.

## Optional Features

#### `capture-stream`

Use the `capture-stream` feature to enable support for streamed packet captures.
This feature is supported only on ubuntu and macosx. 

```toml
[dependencies]
pcap = { version = "0.9", features = ["capture-stream"] }
```

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
