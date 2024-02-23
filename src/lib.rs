//! pcap is a packet capture library available on Linux, Windows and Mac. This
//! crate supports creating and configuring capture contexts, sniffing packets,
//! sending packets to interfaces, listing devices, and recording packet captures
//! to pcap-format dump files.
//!
//! # Capturing packets
//! The easiest way to open an active capture handle and begin sniffing is to
//! use `.open()` on a `Device`. You can obtain the "default" device using
//! `Device::lookup()`, or you can obtain the device(s) you need via `Device::list()`.
//!
//! ```no_run
//! use pcap::Device;
//!
//! let mut cap = Device::lookup().unwrap().unwrap().open().unwrap();
//!
//! while let Ok(packet) = cap.next_packet() {
//!     println!("received packet! {:?}", packet);
//! }
//!
//! ```
//!
//! `Capture`'s `.next_packet()` will produce a `Packet` which can be dereferenced to access the
//! `&[u8]` packet contents.
//!
//! # Custom configuration
//!
//! You may want to configure the `timeout`, `snaplen` or other parameters for the capture
//! handle. In this case, use `Capture::from_device()` to obtain a `Capture<Inactive>`, and
//! proceed to configure the capture handle. When you're finished, run `.open()` on it to
//! turn it into a `Capture<Active>`.
//!
//! ```no_run
//! use pcap::{Device, Capture};
//!
//! let main_device = Device::lookup().unwrap().unwrap();
//! let mut cap = Capture::from_device(main_device).unwrap()
//!                   .promisc(true)
//!                   .snaplen(5000)
//!                   .open().unwrap();
//!
//! while let Ok(packet) = cap.next_packet() {
//!     println!("received packet! {:?}", packet);
//! }
//! ```
//!
//! # Abstracting over different capture types
//!
//! You can abstract over live captures (`Capture<Active>`) and file captures
//! (`Capture<Offline>`) using generics and the [`Activated`] trait, for example:
//!
//! ```
//! use pcap::{Activated, Capture};
//!
//! fn read_packets<T: Activated>(mut capture: Capture<T>) {
//!     while let Ok(packet) = capture.next_packet() {
//!         println!("received packet! {:?}", packet);
//!     }
//! }
//! ```

use std::ffi::{self, CStr};
use std::fmt;

use self::Error::*;

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::HANDLE,
    Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6},
};

mod core;

#[cfg(not(windows))]
pub use core::capture::activated::open_raw_fd;
pub use core::capture::{
    activated::{
        dead::{BpfInstruction, BpfProgram},
        iterator::PacketIter,
        Direction, Savefile, Stat,
    },
    inactive::TimestampType,
    {Activated, Active, Capture, Dead, Inactive, Offline, Precision, State},
};
pub use core::codec::PacketCodec;
pub use core::device::{Address, ConnectionStatus, Device, DeviceFlags, IfFlags};
pub use core::linktype::Linktype;
pub use core::packet::{Packet, PacketHeader};

#[deprecated(note = "Renamed to TimestampType")]
/// An old name for `TimestampType`, kept around for backward-compatibility.
pub type TstampType = TimestampType;

mod raw;

#[cfg(windows)]
pub use sendqueue::sendqueue;

#[cfg(feature = "capture-stream")]
mod stream;
#[cfg(feature = "capture-stream")]
pub use stream::PacketStream;

/// An error received from pcap
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The underlying library returned invalid UTF-8
    MalformedError(std::str::Utf8Error),
    /// The underlying library returned a null string
    InvalidString,
    /// The unerlying library returned an error
    PcapError(String),
    /// The linktype was invalid or unknown
    InvalidLinktype,
    /// The timeout expired while reading from a live capture
    TimeoutExpired,
    /// No more packets to read from the file
    NoMorePackets,
    /// Must be in non-blocking mode to function
    NonNonBlock,
    /// There is not sufficent memory to create a dead capture
    InsufficientMemory,
    /// An invalid input string (internal null)
    InvalidInputString,
    /// An IO error occurred
    IoError(std::io::ErrorKind),
    #[cfg(not(windows))]
    /// An invalid raw file descriptor was provided
    InvalidRawFd,
    /// Errno error
    ErrnoError(errno::Errno),
    /// Buffer size overflows capacity
    BufferOverflow,
}

impl Error {
    unsafe fn new(ptr: *const libc::c_char) -> Error {
        match Self::cstr_to_string(ptr) {
            Err(e) => e as Error,
            Ok(string) => PcapError(string.unwrap_or_default()),
        }
    }

    unsafe fn cstr_to_string(ptr: *const libc::c_char) -> Result<Option<String>, Error> {
        let string = if ptr.is_null() {
            None
        } else {
            Some(CStr::from_ptr(ptr as _).to_str()?.to_owned())
        };
        Ok(string)
    }

    fn with_errbuf<T, F>(func: F) -> Result<T, Error>
    where
        F: FnOnce(*mut libc::c_char) -> Result<T, Error>,
    {
        let mut errbuf = [0i8; 256];
        func(errbuf.as_mut_ptr() as _)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            MalformedError(ref e) => write!(f, "libpcap returned invalid UTF-8: {}", e),
            InvalidString => write!(f, "libpcap returned a null string"),
            PcapError(ref e) => write!(f, "libpcap error: {}", e),
            InvalidLinktype => write!(f, "invalid or unknown linktype"),
            TimeoutExpired => write!(f, "timeout expired while reading from a live capture"),
            NonNonBlock => write!(f, "must be in non-blocking mode to function"),
            NoMorePackets => write!(f, "no more packets to read from the file"),
            InsufficientMemory => write!(f, "insufficient memory"),
            InvalidInputString => write!(f, "invalid input string (internal null)"),
            IoError(ref e) => write!(f, "io error occurred: {:?}", e),
            #[cfg(not(windows))]
            InvalidRawFd => write!(f, "invalid raw file descriptor provided"),
            ErrnoError(ref e) => write!(f, "libpcap os errno: {}", e),
            BufferOverflow => write!(f, "buffer size too large"),
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            MalformedError(..) => "libpcap returned invalid UTF-8",
            PcapError(..) => "libpcap FFI error",
            InvalidString => "libpcap returned a null string",
            InvalidLinktype => "invalid or unknown linktype",
            TimeoutExpired => "timeout expired while reading from a live capture",
            NonNonBlock => "must be in non-blocking mode to function",
            NoMorePackets => "no more packets to read from the file",
            InsufficientMemory => "insufficient memory",
            InvalidInputString => "invalid input string (internal null)",
            IoError(..) => "io error occurred",
            #[cfg(not(windows))]
            InvalidRawFd => "invalid raw file descriptor provided",
            ErrnoError(..) => "internal error, providing errno",
            BufferOverflow => "buffer size too large",
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            MalformedError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<ffi::NulError> for Error {
    fn from(_: ffi::NulError) -> Error {
        InvalidInputString
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(obj: std::str::Utf8Error) -> Error {
        MalformedError(obj)
    }
}

impl From<std::io::Error> for Error {
    fn from(obj: std::io::Error) -> Error {
        IoError(obj.kind())
    }
}

impl From<std::io::ErrorKind> for Error {
    fn from(obj: std::io::ErrorKind) -> Error {
        IoError(obj)
    }
}
