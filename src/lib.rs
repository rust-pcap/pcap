//! pcap is a packet capture library available on Linux, Windows and Mac. This
//! crate supports creating and configuring capture contexts, sniffing packets,
//! sending packets to interfaces, listing devices, and recording packet captures
//! to pcap-format dump files.
//!
//! # Getting devices
//! The first step to packet sniffing using pcap is picking which device you want
//! to capture from. `Device::lookup()` returns a `Device` that contains the first
//! non-loopback device pcap is aware of. You can also use `Device::list()` to 
//! obtain a list of `Device`s for capturing.
//!
//! ```ignore
//! use pcap::Device;
//!
//! fn main() {
//!     let main_device = Device::lookup().unwrap();
//!     println!("Device name: {}", main_device.name);
//! }
//! ```
//!
//! # Capturing packets
//! The easiest way to open an active capture handle and begin sniffing is to
//! use `.open()` on a `Device`.
//!
//! ```ignore
//! use pcap::Device;
//! 
//! fn main() {
//!     let mut cap = Device::lookup().unwrap().open().unwrap();
//!     
//!     while let Some(packet) = cap.next() {
//!         println!("received packet! {:?}", packet);
//!     }
//! }
//! ```
//! 
//! `Capture`'s `.next()` will produce a `Packet` which can be dereferenced to access the
//! `&[u8]` packet contents.
//!
//! # Custom configuration
//! 
//! You may want to configure the `timeout`, `snaplen` or other parameters for the capture
//! handle. In this case, use `Capture::from_device()` to obtain a `Capture<Inactive>`, and
//! proceed to configure the capture handle. When you're finished, run `.open()` on it to
//! turn it into a `Capture<Active>`.
//!
//! ```ignore
//! use pcap::{Device,Capture};
//! 
//! fn main() {
//!     let main_device = Device::lookup().unwrap();
//!     let mut cap = Capture::from_device(main_device).unwrap()
//!                       .promisc(true)
//!                       .snaplen(5000)
//!                       .open().unwrap();
//!     
//!     // ...
//! }
//! ```

extern crate libc;

use unique::Unique;
use std::marker::PhantomData;
use std::ptr;
use std::ffi::{CStr,CString};
use std::path::Path;
use std::slice;
use std::ops::Deref;
use std::mem::transmute;
use std::str;
use std::fmt;
use self::Error::*;

mod raw;
mod unique;

const PCAP_ERROR_NOT_ACTIVATED: i32 = -3;
const PCAP_ERRBUF_SIZE: usize = 256;

/// An error received from pcap
#[derive(Debug)]
pub enum Error {
    MalformedError(str::Utf8Error),
    InvalidString,
    PcapError(String),
    InvalidLinktype
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
                write!(f, "pcap returned a string that was not encoded properly: {}", e)
            },
            InvalidString => {
                write!(f, "pcap returned an invalid (null) string")
            },
            PcapError(ref e) => {
                write!(f, "pcap error: {}", e)
            },
            InvalidLinktype => {
                write!(f, "invalid or unknown linktype")
            }
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            MalformedError(..) => "message from pcap is not encoded properly",
            PcapError(..) => "pcap FFI error",
            InvalidString => "pcap returned an invalid (null) string",
            InvalidLinktype => "invalid or unknown linktype"
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

#[derive(Debug)]
/// A network device name and (potentially) pcap's description of it.
pub struct Device {
    pub name: String,
    pub desc: Option<String>
}

impl Device {
    /// Opens a `Capture<Active>` on this device.
    pub fn open(self) -> Result<Capture<Active>, Error> {
        Ok(try!(try!(Capture::from_device(self)).open()))
    }

    /// Returns the default Device suitable for captures according to pcap_lookupdev,
    /// or an error from pcap.
    pub fn lookup() -> Result<Device, Error> {
        let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];

        unsafe {
            let default_name = raw::pcap_lookupdev(errbuf.as_mut_ptr());

            if default_name.is_null() {
                return Error::new(errbuf.as_ptr());
            }

            Ok(Device {
                name: try!(cstr_to_string(default_name)),
                desc: None
            })
        }
    }

    /// Returns a vector of `Device`s known by pcap via pcap_findalldevs.
    pub fn list() -> Result<Vec<Device>, Error> {
        unsafe {
            let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];
            let mut dev_buf: *mut raw::Struct_pcap_if = ptr::null_mut();
            let mut ret = vec![];

            match raw::pcap_findalldevs(&mut dev_buf, errbuf.as_mut_ptr()) {
                0 => {
                    let mut cur = dev_buf;

                    while !cur.is_null() {
                        ret.push(Device {
                            name: cstr_to_string((&*cur).name).unwrap(),
                            desc: {
                                if !(&*cur).description.is_null() {
                                    Some(cstr_to_string((&*cur).description).unwrap())
                                } else {
                                    None
                                }
                            }
                        });

                        cur = (&*cur).next;
                    }

                    raw::pcap_freealldevs(dev_buf);

                    Ok(ret)
                },
                _ => {
                    Error::new(errbuf.as_ptr())
                }
            }
        }
    }
}

impl<'a> Into<Device> for &'a str {
    fn into(self) -> Device {
        Device {
            name: self.into(),
            desc: None
        }
    }
}

/// This is a datalink link type.
///
/// As an example, `Linktype(1)` is ethernet. A full list of linktypes is available
/// [here](http://www.tcpdump.org/linktypes.html).
#[derive(Debug, PartialEq, Eq)]
pub struct Linktype(pub i32);

impl Linktype {
    /// Gets the name of the link type, such as EN10MB
    pub fn get_name(&self) -> Result<String, Error> {
        unsafe {
            let name = raw::pcap_datalink_val_to_name(self.0);

            if name.is_null() {
                return Err(InvalidLinktype)
            } else {
                Ok(try!(cstr_to_string(name)))
            }
        }
    }

    /// Gets the description of a link type.
    pub fn get_description(&self) -> Result<String, Error> {
        unsafe {
            let description = raw::pcap_datalink_val_to_description(self.0);

            if description.is_null() {
                return Err(InvalidLinktype)
            } else {
                Ok(try!(cstr_to_string(description)))
            }
        }
    }
}

/// Represents a packet returned from pcap. This can be dereferenced to access
/// the underlying packet `[u8]` slice.
pub struct Packet<'a> {
    header: &'a raw::Struct_pcap_pkthdr,
    data: &'a libc::c_uchar
}

impl<'b> Deref for Packet<'b> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self.data, self.header.caplen as usize)
        }
    }
}

impl<'a> fmt::Debug for Packet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.deref().fmt(f)
    }
}

/// Phantom type representing an inactive capture handle.
pub enum Inactive {}
/// Phantom type representing an active capture handle. Implements `Activated` because
/// you can do pretty much all of the same things with it that you can do with a live
/// capture.
pub enum Active {}
/// Phantom type representing an offline capture handle, from a pcap dump file.
/// Implements `Activated`.
pub enum Offline {}

pub trait Activated: State {}

impl Activated for Active {}
impl Activated for Offline {}

/// `Capture`s can be in different states at different times, and in these states they
/// may or may not have particular capabilities. This trait is implemented by phantom
/// types which allows us to punt these invariants to the type system to avoid runtime
/// errors.
pub trait State {}

impl State for Inactive {}
impl State for Active {}
impl State for Offline {}

/// This is a pcap capture handle which is an abstraction over the `pcap_t` provided by pcap.
/// There are many ways to instantiate and interact with a pcap handle, so phantom types are
/// used to express these behaviors.
///
/// **`Capture<Inactive>`** is created via `Capture::from_device()`. This handle is inactive,
/// so you cannot (yet) obtain packets from it. However, you can configure things like the
/// buffer size, snaplen, timeout, and promiscuity before you activate it.
///
/// **`Capture<Active>`** is created by calling `.open()` on a `Capture<Inactive>`. This
/// activates the capture handle, allowing you to get packets with `.next()` or apply filters
/// with `.filter()`.
///
/// **`Capture<Offline>`** is created via `Capture::from_file()`. This allows you to read a
/// pcap format dump file as if you were opening an interface -- very useful for testing or 
/// analysis.
///
/// # Example:
///
/// ```ignore
/// let cap = Capture::from_device(Device::lookup().unwrap()) // open the "default" interface
///               .unwrap() // assume the device exists and we are authorized to open it
///               .open() // activate the handle
///               .unwrap(); // assume activation worked
///
/// while let Some(packet) = cap.next() {
///     println!("received packet! {:?}", packet);
/// }
/// ```
pub struct Capture<T: State> {
    handle: Unique<raw::pcap_t>,
    _marker: PhantomData<T>
}

impl Capture<Offline> {
    /// Opens an offline capture handle from a pcap dump file, given a path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Capture<Offline>, Error> {
        let name = CString::new(path.as_ref().to_str().unwrap()).unwrap();
        let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];

        unsafe {
            let handle = raw::pcap_open_offline(name.as_ptr(), errbuf.as_mut_ptr());
            if handle.is_null() {
                return Error::new(errbuf.as_ptr());
            }

            Ok(Capture {
                handle: Unique::new(handle),
                _marker: PhantomData
            })
        }
    }
}

impl Capture<Inactive> {
    /// Opens a capture handle for a device. You can pass a `Device` or an `&str` device
    /// name here. The handle is inactive, but can be activated via `.open()`.
    pub fn from_device<D: Into<Device>>(device: D) -> Result<Capture<Inactive>, Error> {
        let device: Device = device.into();
        let name = CString::new(device.name).unwrap();
        let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];

        unsafe {
            let handle = raw::pcap_create(name.as_ptr(), errbuf.as_mut_ptr());
            if handle.is_null() {
                return Error::new(errbuf.as_ptr());
            }

            Ok(Capture {
                handle: Unique::new(handle),
                _marker: PhantomData
            })
        }
    }

    /// Activates an inactive capture created from `Capture::from_device()` or returns
    /// an error.
    pub fn open(self) -> Result<Capture<Active>, Error> {
        unsafe {
            let cap = transmute::<Capture<Inactive>, Capture<Active>>(self);

            if 0 != raw::pcap_activate(*cap.handle) {
                return Error::new(raw::pcap_geterr(*cap.handle));
            }

            Ok(cap)
        }
    }

    /// Set the read timeout for the Capture. By default, this is 0, so it will block
    /// indefinitely.
    pub fn timeout(self, ms: i32) -> Capture<Inactive> {
        unsafe {
            raw::pcap_set_timeout(*self.handle, ms);
            self
        }
    }

    /// Set promiscuous mode on or off. By default, this is off.
    pub fn promisc(self, to: bool) -> Capture<Inactive> {
        unsafe {
            raw::pcap_set_promisc(*self.handle, if to {1} else {0});
            self
        }
    }

    /// Set rfmon mode on or off. The default is maintained by pcap.
    pub fn rfmon(self, to: bool) -> Capture<Inactive> {
        unsafe {
            raw::pcap_set_rfmon(*self.handle, if to {1} else {0});
            self
        }
    }

    /// Set the buffer size for incoming packet data.
    ///
    /// The default is 1000000. This should always be larger than the snaplen.
    pub fn buffer_size(self, to: i32) -> Capture<Inactive> {
        unsafe {
            raw::pcap_set_buffer_size(*self.handle, to);
            self
        }
    }

    /// Set the snaplen size (the maximum length of a packet captured into the buffer).
    /// Useful if you only want certain headers, but not the entire packet.
    /// 
    /// The default is 65535
    pub fn snaplen(self, to: i32) -> Capture<Inactive> {
        unsafe {
            raw::pcap_set_snaplen(*self.handle, to);
            self
        }
    }
}

///# Activated captures include `Capture<Active>` and `Capture<Offline>`.
impl<T: Activated> Capture<T> {
    /// List the datalink types that this captured device supports.
    pub fn list_datalinks(&self) -> Result<Vec<Linktype>, Error> {
        unsafe {
            let mut links: *mut i32 = ptr::null_mut();

            let num = raw::pcap_list_datalinks(*self.handle, &mut links);

            if num == PCAP_ERROR_NOT_ACTIVATED {
                raw::pcap_free_datalinks(links);
                panic!("It should not be possible to run list_datalinks on a Capture that is not activated, please report this bug!")
            } else if num < 0 {
                raw::pcap_free_datalinks(links);
                Error::new(raw::pcap_geterr(*self.handle))
            } else {
                let slice = slice::from_raw_parts(links, num as usize).iter().map(|&a| Linktype(a)).collect();
                raw::pcap_free_datalinks(links);

                Ok(slice)
            }
        }
    }

    /// Set the datalink type for the current capture handle.
    pub fn set_datalink(&mut self, linktype: Linktype) -> Result<(), Error> {
        unsafe {
            match raw::pcap_set_datalink(*self.handle, linktype.0) {
                0 => {
                    Ok(())
                },
                _ => {
                    Error::new(raw::pcap_geterr(*self.handle))
                }
            }
        }
    }

    /// Get the current datalink type for this capture handle.
    pub fn get_datalink(&self) -> Linktype {
        unsafe {
            match raw::pcap_datalink(*self.handle) {
                PCAP_ERROR_NOT_ACTIVATED => {
                    panic!("It should not be possible to run get_datalink on a Capture that is not activated, please report this bug!");
                },
                lt => {
                    Linktype(lt)
                }
            }
        }
    }

    /// Create a `Savefile` context for recording captured packets using this `Capture`'s
    /// configurations.
    pub fn savefile<P: AsRef<Path>>(&self, path: P) -> Result<Savefile, Error> {
        let name = CString::new(path.as_ref().to_str().unwrap()).unwrap();
        unsafe {
            let handle = raw::pcap_dump_open(*self.handle, name.as_ptr());

            if handle.is_null() {
                Error::new(raw::pcap_geterr(*self.handle))
            } else {
                Ok(Savefile {
                    handle: Unique::new(handle)
                })
            }
        }
    }

    /// Blocks until a packet is returned from the capture handle or an error occurs.
    ///
    /// pcap captures packets and places them into a buffer which this function reads
    /// from. This buffer has a finite length, so if the buffer fills completely new
    /// packets will be discarded temporarily. This means that in realtime situations,
    /// you probably want to minimize the time between calls of this next() method.
    pub fn next<'a>(&'a mut self) -> Option<Packet<'a>> {
        unsafe {
            let mut header: *mut raw::Struct_pcap_pkthdr = ptr::null_mut();
            let mut packet: *const libc::c_uchar = ptr::null();
            match raw::pcap_next_ex(*self.handle, &mut header, &mut packet) {
                1 => {
                    // packet was read without issue
                    Some(Packet {
                        header: &*header,
                        data: &*packet
                    })
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

impl Capture<Active> {
    /// Sends a packet over this capture handle's interface, returning the number
    /// of bytes written.
    pub fn sendpacket<'a>(&mut self, buf: &'a [u8]) -> Result<usize, Error> {
        unsafe {
            let written = raw::pcap_inject(*self.handle, buf.as_ptr() as *const libc::types::common::c95::c_void, buf.len() as libc::types::os::arch::c95::size_t);

            match written {
                -1 => {
                    return Error::new(raw::pcap_geterr(*self.handle));
                },
                _ => {
                    Ok(written as usize)
                }
            }
        }
    }
}

impl<T: State> Drop for Capture<T> {
    fn drop(&mut self) {
        unsafe {
            raw::pcap_close(*self.handle)
        }
    }
}

/// Abstraction for writing pcap savefiles, which can be read afterwards via `Capture::from_file()`.
pub struct Savefile {
    handle: Unique<raw::pcap_dumper_t>
}

impl Savefile {
    pub fn write<'a>(&mut self, packet: &'a Packet<'a>) {
        unsafe {
            raw::pcap_dump(*self.handle as *mut u8, packet.header, packet.data);
        }
    }
}

impl Drop for Savefile {
    fn drop(&mut self) {
        unsafe {
            raw::pcap_dump_close(*self.handle);
        }
    }
}

#[inline]
fn cstr_to_string(ptr: *const libc::c_char) -> Result<String, Error> {
    if ptr.is_null() {
        Err(InvalidString)
    } else {
        Ok(try!(str::from_utf8(unsafe{CStr::from_ptr(ptr)}.to_bytes())).into())
    }
}
