#![feature(libc, unique)]

extern crate libc;

use std::ptr::{self, Unique};
use std::ffi::{CStr,CString};
use std::default::Default;
use std::path::Path;
use std::slice;
use std::str;
use std::fmt;
use std::convert::From;
mod raw;

use self::Error::*;

/// An error received from pcap
#[derive(Debug)]
pub enum Error {
    MalformedError(str::Utf8Error),
    PcapError(String)
}

impl Error {
    fn new<T>(ptr: *const libc::c_char) -> Result<T, Error> {
        Err(PcapError(try!(cstr_to_string(ptr))))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MalformedError(e) => {
                write!(f, "pcap returned an error that was not encoded properly: {}", e)
            },
            PcapError(ref e) => {
                write!(f, "pcap error: {}", e)
            }
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            MalformedError(..) => "error message from pcap is invalid",
            PcapError(..) => "pcap FFI error"
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            MalformedError(ref e) => Some(e),
            _ => None
        }
    }
}

impl From<str::Utf8Error> for Error {
    fn from(obj: str::Utf8Error) -> Error {
        MalformedError(obj)
    }
}

/// An iterator over devices that pcap is aware about on the system.
pub struct Devices {
    orig: Unique<raw::Struct_pcap_if>,
    device: Unique<raw::Struct_pcap_if>
}

impl Devices {
    /// Construct a new `Devices` iterator by internally using `pcap_findalldevs()`
    pub fn list_all() -> Result<Devices, Error> {
        unsafe {
            let mut errbuf = [0i8; 256];
            let mut dev_buf: *mut raw::Struct_pcap_if = ptr::null_mut();

            match raw::pcap_findalldevs(&mut dev_buf, errbuf.as_mut_ptr()) {
                0 => {
                    Ok(Devices {
                        orig: Unique::new(dev_buf),
                        device: Unique::new(dev_buf)
                    })
                },
                _ => {
                    Error::new(errbuf.as_ptr())
                }
            }
        }
    }
}

impl Iterator for Devices {
    type Item = Device;

    fn next(&mut self) -> Option<Device> {
        if self.device.is_null() {
            None
        } else {
            unsafe {
                let ret = Device {
                    name: cstr_to_string(self.device.get().name).unwrap(),
                    desc: {
                        if !self.device.get().description.is_null() {
                            Some(cstr_to_string(self.device.get().description).unwrap())
                        } else {
                            None
                        }
                    }
                };
                self.device = Unique::new(self.device.get().next);

                Some(ret)
            }
        }
    }
}

impl Drop for Devices {
    fn drop(&mut self) {
        unsafe {
            raw::pcap_freealldevs(*self.orig);
        }
    }
}

#[derive(Debug)]
/// A network device as returned from `Devices::list_all()`.
pub struct Device {
    pub name: String,
    pub desc: Option<String>
}

impl AsRef<str> for Device {
    fn as_ref(&self) -> &str {
        &*self.name
    }
}

/// This is a builder for a `Capture` handle. It's useful when you want to specify certain
/// parameters, like promiscuous mode, or buffer length, before opening.
///
/// You can use `Capture::from_device()` instead of this builder, with less flexibility.
pub struct CaptureBuilder {
    buffer_size: i32,
    snaplen: i32,
    promisc: i32,
    rfmon: Option<i32>,
    timeout: i32,
}

impl CaptureBuilder {
    /// Creates a `CaptureBuilder` with sensible defaults.
    pub fn new() -> CaptureBuilder {
        CaptureBuilder {
            buffer_size: 1000000,
            snaplen: 65535,
            promisc: 0,
            rfmon: None,
            timeout: 0
        }
    }

    /// Open a `Capture` with this `CaptureBuilder` with the given device. You can
    /// provide a `Device` or an &str name of the device/source you would like to open.
    pub fn open<D: AsRef<str>>(&self, device: D) -> Result<Capture, Error> {
        let name = CString::new(device.as_ref()).unwrap();
        // TODO: handle errors better throughout this library
        let mut errbuf = [0i8; 256];

        unsafe {
            let handle = raw::pcap_create(name.as_ptr(), errbuf.as_mut_ptr());
            if handle.is_null() {
                return Error::new(errbuf.as_ptr());
            }

            let cap = Capture {
                handle: Unique::new(handle)
            };

            raw::pcap_set_snaplen(handle, self.snaplen);
            raw::pcap_set_buffer_size(handle, self.buffer_size);
            raw::pcap_set_promisc(handle, self.promisc);
            match self.rfmon {
                Some(rfmon) => {
                    raw::pcap_set_rfmon(handle, rfmon);
                },
                None => {}
            };
            raw::pcap_set_timeout(handle, self.timeout);

            if 0 != raw::pcap_activate(handle) {
                return Error::new(raw::pcap_geterr(handle));
            }

            Ok(cap)
        }
    }

    /// Set the read timeout for the Capture. By default, this is 0, so it will block
    /// indefinitely.
    pub fn timeout(&mut self, ms: i32) -> &mut CaptureBuilder {
        self.timeout = ms;
        self
    }

    /// Set promiscuous mode on or off. By default, this is off.
    pub fn promisc(&mut self, to: bool) -> &mut CaptureBuilder {
        self.promisc = if to {1} else {0};
        self
    }

    /// Set rfmon mode on or off. The default is maintained by pcap.
    pub fn rfmon(&mut self, to: bool) -> &mut CaptureBuilder {
        self.rfmon = Some(if to {1} else {0});
        self
    }

    /// Set the buffer size for incoming packet data.
    ///
    /// The default is 1000000. This should always be larger than the snaplen.
    pub fn buffer_size(&mut self, to: i32) -> &mut CaptureBuilder {
        self.buffer_size = to;
        self
    }

    /// Set the snaplen size (the maximum length of a packet captured into the buffer).
    /// Useful if you only want certain headers, but not the entire packet.
    /// 
    /// The default is 65535
    pub fn snaplen(&mut self, to: i32) -> &mut CaptureBuilder {
        self.snaplen = to;
        self
    }
}

/// This represents an open capture handle attached to a device or file.
///
/// Internally it represents a `pcap_t`.
pub struct Capture {
    handle: Unique<raw::pcap_t>
}

impl Capture {
    /// Creates a capture handle from the specified device, or an error from pcap.
    ///
    /// You can provide this a `Device` from `Devices::list_all()` or an `&str` name of
    /// the device such as "any" on Linux.
    pub fn from_device<D: AsRef<str>>(device: D) -> Result<Capture, Error> {
        CaptureBuilder::new().open(device)
    }

    /// Creates a capture handle from the specified file, or an error from pcap.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Capture, Error> {
        let name = CString::new(path.as_ref().to_str().unwrap()).unwrap();
        let mut errbuf = [0i8; 256];

        unsafe {
            let handle = raw::pcap_open_offline(name.as_ptr(), errbuf.as_mut_ptr());
            if handle.is_null() {
                return Error::new(errbuf.as_ptr());
            }

            let cap = Capture {
                handle: Unique::new(handle)
            };

            Ok(cap)
        }
    }

    /// Blocks until a packet is returned from the capture handle or an error occurs.
    pub fn next<'a>(&'a mut self) -> Option<&'a [u8]> {
        unsafe {
            let mut header: *mut raw::Struct_pcap_pkthdr = ptr::null_mut();
            let mut packet: *const libc::c_uchar = ptr::null_mut();
            match raw::pcap_next_ex(*self.handle, &mut header, &mut packet) {
                1 => {
                    // packet was read without issue
                    Some(slice::from_raw_parts(packet, (*header).len as usize))
                },
                _ => {
                    None
                }
            }
        }
    }

    /// Adds a filter to the capture using the given BPF program string. Internally
    /// this is compiled using `pcap_compile()`.
    ///
    /// See http://biot.com/capstats/bpf.html for more information about this syntax.
    pub fn filter(&mut self, program: &str) -> Result<(), Error> {
        let program = CString::new(program).unwrap();

        unsafe {
            let mut bpf_program: raw::Struct_bpf_program = Default::default();

            if -1 == raw::pcap_compile(*self.handle, &mut bpf_program, program.as_ptr(), 0, 0) {
                return Error::new(raw::pcap_geterr(*self.handle));
            }

            if -1 == raw::pcap_setfilter(*self.handle, &mut bpf_program) {
                raw::pcap_freecode(&mut bpf_program);
                return Error::new(raw::pcap_geterr(*self.handle));
            }

            raw::pcap_freecode(&mut bpf_program);
            Ok(())
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        unsafe {
            raw::pcap_close(*self.handle)
        }
    }
}

fn cstr_to_string(ptr: *const libc::c_char) -> Result<String, str::Utf8Error> {
    Ok(try!(str::from_utf8(unsafe{CStr::from_ptr(ptr)}.to_bytes())).to_string())
}
