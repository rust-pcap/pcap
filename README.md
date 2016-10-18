# pcap [![Build status](https://api.travis-ci.org/ebfull/pcap.svg)](https://travis-ci.org/ebfull/pcap) [![Crates.io](https://img.shields.io/crates/v/pcap.svg)](https://crates.io/crates/pcap) #

### [Documentation](https://ebfull.github.io/pcap/)

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

Place wpcap.dll in your `C:\Rust\bin\rustlib\x86_64-pc-windows-gnu\lib\` directory on 64 bit
or `C:\Rust\bin\rustlib\i686-pc-windows-gnu\lib\` on 32 bit.

## Linux

On Debian based Linux, install `libpcap-dev`. If not running as root, you need to set capabilities like so: ```sudo setcap cap_net_raw,cap_net_admin=eip path/to/bin```

## Mac OS X

libpcap should be installed on Mac OS X by default.

**Note:** A timeout of zero may cause ```pcap::Capture::next``` to hang and never return (because it waits for the timeout to expire before returning). This can be fixed by using a non-zero timeout (as the libpcap manual recommends) and calling ```pcap::Capture::next``` in a loop.

## Optional Features

To get access to the `Capture::savefile_append` function (which allows appending
to an existing pcap file) you have to depend on the `pcap-savefile-append`
feature flag. It requires at least libpcap version 1.7.2.

    [dependencies]
    pcap = { version = "*", features = "pcap-savefile-append" }

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
