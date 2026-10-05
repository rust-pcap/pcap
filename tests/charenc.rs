//! Capture file paths that are not plain ASCII.
//!
//! On Windows libpcap reads the path in the local code page unless pcap_init has been asked for
//! UTF-8, and that choice is made once for the whole process and cannot be taken back. These
//! tests therefore need a test binary to themselves.
#![cfg(any(not(windows), libpcap_1_10_0))]

use std::fs;

use tempfile::TempDir;

use pcap::{Capture, Linktype};

/// "capture", in four scripts. libpcap converts the path with one call that does not care which
/// script it is looking at, so these cover the encoding widths rather than the languages.
const NAMES: &[&str] = &[
    "захват",     // Russian, two-byte
    "捕获",       // Chinese, three-byte
    "कैप्चर",       // Hindi, three-byte with combining marks
    "𝄞capture🎯", // Astral plane, four-byte
];

#[cfg(not(windows))]
fn use_utf8_paths() -> bool {
    true
}

// wpcap.dll may predate pcap_init, in which case the path stays in the local code page and
// there is nothing here to test.
#[cfg(windows)]
fn use_utf8_paths() -> bool {
    pcap::init(pcap::CharEncoding::Utf8).is_ok()
}

#[test]
fn savefile_round_trip_non_ascii_paths() {
    if !use_utf8_paths() {
        return;
    }

    let dir = TempDir::new().unwrap();

    for name in NAMES {
        // The name is used for a directory as well as for the file, since libpcap converts the
        // whole path and a directory component has to work just as a file name does.
        let subdir = dir.path().join(name);
        fs::create_dir(&subdir).unwrap();
        let tmpfile = subdir.join(format!("{name}.pcap"));

        let cap = Capture::dead(Linktype(1)).unwrap();
        let save = cap.savefile(&tmpfile).unwrap();
        drop(save);

        assert!(
            tmpfile.exists(),
            "{name} was not written where it was asked for"
        );

        Capture::from_file(&tmpfile).unwrap();
    }
}
