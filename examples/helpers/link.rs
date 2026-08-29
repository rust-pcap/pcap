//! Trigger linking against the appropriate library for example binaries.

#[cfg(not(windows))]
#[link(name = "pcap")]
extern "C" {}

#[cfg(windows)]
#[link(name = "wpcap")]
extern "C" {}
