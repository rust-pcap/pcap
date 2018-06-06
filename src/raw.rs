#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![cfg_attr(feature = "clippy", allow(unreadable_literal))]
// See https://github.com/rust-lang-nursery/rust-bindgen/pull/1157.
#![cfg_attr(feature = "clippy", allow(zero_ptr))]

use libc::FILE;

include!("pcap.rs");

#[cfg(windows)]
#[link(name = "wpcap")]
extern "C" {}

#[cfg(not(windows))]
#[link(name = "pcap")]
extern "C" {}
