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

If `PCAP_LIBDIR` environment variable is set when building the crate, it will be added to the linker search path - this allows linking against a specific `libpcap`.

## Optional Features

#### `tokio`

Use the `tokio` feature to enable support for streamed packet captures.

```toml
[dependencies]
pcap = { version = "0.7", features = ["tokio"] }
```

#### `pcap-savefile-append`

To get access to the `Capture::savefile_append` function (which allows appending
to an existing pcap file) you have to depend on the `pcap-savefile-append`
feature flag. It requires at least libpcap version 1.7.2.

```toml
[dependencies]
pcap = { version = "0.7", features = ["pcap-savefile-append"] }
```

#### `pcap-fopen-offline-precision`

To enable `Capture::from_raw_fd_with_precision` constructor (which allows opening
an offline capture from a raw file descriptor with a predefined timestamp precision)
you have to add `pcap-fopen-offline-precision` feature flag. This requires libpcap
version 1.5.0 or later.

```toml
[dependencies]
pcap = { version = "0.7", features = ["pcap-fopen-offline-precision"] }
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
