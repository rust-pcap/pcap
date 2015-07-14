# pcap [![Build status](https://api.travis-ci.org/ebfull/pcap.svg)](https://travis-ci.org/ebfull/pcap) [![Crates.io](https://img.shields.io/crates/v/pcap.svg)](https://crates.io/crates/pcap) #

[Documentation](http://www.rust-ci.org/ebfull/pcap/doc/pcap/)

This is a **Rust language** crate for accessing the packet sniffing capabilities of pcap (or wpcap on Windows).
It is limited in functionality, so if you need anything feel free to post an issue or submit a pull request!

* List devices
* Open capture handle on a device or file
* Configure some parameters like promiscuity and buffer length
* Get packets from the capture handle

See examples for usage.

# Building

## Windows

Install [WinPcap](http://www.winpcap.org/install/default.htm).

Place wpcap.dll in your `C:\Rust\bin\rustlib\x86_64-pc-windows-gnu\lib\` directory on 64 bit
or `C:\Rust\bin\rustlib\i686-pc-windows-gnu\lib\` on 32 bit.

## Linux

On Debian based Linux, install `libpcap-dev`.

## Mac OS X

libpcap should be installed on Mac OS X by default.

**Note:** A timeout of zero may cause ```pcap::Capture::next``` to hang and never return (because it waits for the timeout to expire before returning). This can be fixed by using a non-zero timeout (as the libpcap manual recommends) and calling ```pcap::Capture::next``` in a loop.
