use std::path::Path;

#[cfg(not(windows))]
use std::os::unix::io::RawFd;

use crate::{
    capture::{Capture, Offline},
    raw, Error,
};

#[cfg(libpcap_1_5_0)]
use crate::capture::Precision;

#[cfg(not(windows))]
use crate::capture::activated::open_raw_fd;

impl Capture<Offline> {
    /// Opens an offline capture handle from a pcap dump file, given a path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Capture<Offline>, Error> {
        Capture::new_raw(path.as_ref().to_str(), |path, err| unsafe {
            raw::pcap_open_offline(path, err)
        })
    }

    /// Opens an offline capture handle from a pcap dump file, given a path.
    /// Takes an additional precision argument specifying the time stamp precision desired.
    #[cfg(libpcap_1_5_0)]
    pub fn from_file_with_precision<P: AsRef<Path>>(
        path: P,
        precision: Precision,
    ) -> Result<Capture<Offline>, Error> {
        Capture::new_raw(path.as_ref().to_str(), |path, err| unsafe {
            raw::pcap_open_offline_with_tstamp_precision(path, precision as _, err)
        })
    }

    /// Opens an offline capture handle from a pcap dump file, given a file descriptor.
    ///
    /// # Safety
    ///
    /// Unsafe, because the returned Capture assumes it is the sole owner of the file descriptor.
    #[cfg(not(windows))]
    pub unsafe fn from_raw_fd(fd: RawFd) -> Result<Capture<Offline>, Error> {
        open_raw_fd(fd, b'r')
            .and_then(|file| Capture::new_raw(None, |_, err| raw::pcap_fopen_offline(file, err)))
    }

    /// Opens an offline capture handle from a pcap dump file, given a file descriptor. Takes an
    /// additional precision argument specifying the time stamp precision desired.
    ///
    /// # Safety
    ///
    /// Unsafe, because the returned Capture assumes it is the sole owner of the file descriptor.
    #[cfg(all(not(windows), libpcap_1_5_0))]
    pub unsafe fn from_raw_fd_with_precision(
        fd: RawFd,
        precision: Precision,
    ) -> Result<Capture<Offline>, Error> {
        open_raw_fd(fd, b'r').and_then(|file| {
            Capture::new_raw(None, |_, err| {
                raw::pcap_fopen_offline_with_tstamp_precision(file, precision as _, err)
            })
        })
    }

    /// Get the major version number of the pcap dump file format.
    pub fn major_version(&self) -> i32 {
        unsafe { raw::pcap_major_version(self.handle.as_ptr()) }
    }

    /// Get the minor version number of the pcap dump file format.
    pub fn minor_version(&self) -> i32 {
        unsafe { raw::pcap_minor_version(self.handle.as_ptr()) }
    }

    /// Get the (major, minor) version number of the pcap dump file format.
    pub fn version(&self) -> (i32, i32) {
        (self.major_version(), self.minor_version())
    }
}
