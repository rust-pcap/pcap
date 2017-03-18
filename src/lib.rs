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
//! ```ignore
//! use pcap::Device;
//!
//! fn main() {
//!     let mut cap = Device::lookup().unwrap().open().unwrap();
//!
//!     while let Ok(packet) = cap.next() {
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
//!     while let Ok(packet) = cap.next() {
//!         println!("received packet! {:?}", packet);
//!     }
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
#[cfg(not(windows))]
use std::os::unix::io::{RawFd, AsRawFd};

pub use raw::PacketHeader;

mod raw;
mod unique;

const PCAP_ERROR_NOT_ACTIVATED: i32 = -3;
const PCAP_ERRBUF_SIZE: usize = 256;

/// An error received from pcap
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    MalformedError(str::Utf8Error),
    InvalidString,
    PcapError(String),
    InvalidLinktype,
    TimeoutExpired,
    NoMorePackets,
    InsufficientMemory,
    #[cfg(not(windows))]
    InvalidRawFd,
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
            },
            TimeoutExpired => {
               write!(f, "timeout expired")
            },
            NoMorePackets => {
               write!(f, "no more packets to read from the file")
            },
            InsufficientMemory => {
                write!(f, "insufficient memory")
            },
            #[cfg(not(windows))]
            InvalidRawFd => {
                write!(f, "invalid raw file descriptor")
            },
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            MalformedError(..) => "message from pcap is not encoded properly",
            PcapError(..) => "pcap FFI error",
            InvalidString => "pcap returned an invalid (null) string",
            InvalidLinktype => "invalid or unknown linktype",
            TimeoutExpired => "pcap was reading from a live capture and the timeout expired",
            NoMorePackets => "pcap was reading from a file and there were no more packets to read",
            InsufficientMemory => "insufficient memory",
            #[cfg(not(windows))]
            InvalidRawFd => "invalid raw file descriptor",
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
            let default_name = raw::pcap_lookupdev(errbuf.as_mut_ptr() as *mut _);

            if default_name.is_null() {
                return Error::new(errbuf.as_ptr() as *const _);
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

            match raw::pcap_findalldevs(&mut dev_buf, errbuf.as_mut_ptr() as *mut _) {
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
                    Error::new(errbuf.as_ptr() as *mut _)
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
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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

/// Represents a packet returned from pcap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    pub header: &'a PacketHeader,
    pub data: &'a [u8]
}

impl<'b> Deref for Packet<'b> {
   type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.data
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Stat {
    pub received: u32,
    pub dropped: u32,
    pub if_dropped: u32
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Precision {
    Micro = 0,
    Nano = 1,
}

/// Phantom type representing an inactive capture handle.
pub enum Inactive {}
/// Phantom type representing an active capture handle.
pub enum Active {}
/// Phantom type representing an offline capture handle, from a pcap dump file.
/// Implements `Activated` because it behaves nearly the same as a live handle.
pub enum Offline {}
/// Phantom type representing a dead capture handle.  This can be use to create
/// new save files that are not generated from an active capture.
/// Implements `Activated` because it behaves nearly the same as a live handle.
pub enum Dead {}

pub unsafe trait Activated: State {}

unsafe impl Activated for Active {}
unsafe impl Activated for Offline {}
unsafe impl Activated for Dead {}

/// `Capture`s can be in different states at different times, and in these states they
/// may or may not have particular capabilities. This trait is implemented by phantom
/// types which allows us to punt these invariants to the type system to avoid runtime
/// errors.
pub unsafe trait State {}

unsafe impl State for Inactive {}
unsafe impl State for Active {}
unsafe impl State for Offline {}
unsafe impl State for Dead {}

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
/// **`Capture<Dead>`** is created via `Capture::dead()`. This allows you to create a pcap
/// format dump file without needing an active capture.
///
/// # Example:
///
/// ```ignore
/// let cap = Capture::from_device(Device::lookup().unwrap()) // open the "default" interface
///               .unwrap() // assume the device exists and we are authorized to open it
///               .open() // activate the handle
///               .unwrap(); // assume activation worked
///
/// while let Ok(packet) = cap.next() {
///     println!("received packet! {:?}", packet);
/// }
/// ```
pub struct Capture<T: State + ?Sized> {
    handle: Unique<raw::pcap_t>,
    _marker: PhantomData<T>
}

impl<T: State + ?Sized> Capture<T> {
    fn new_raw<F>(path: Option<&str>, func: F) -> Result<Capture<T>, Error>
        where F: FnOnce(*const libc::c_char, *mut libc::c_char) -> *mut raw::pcap_t
    {
        let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];
        unsafe {
            let handle = match path {
                None => func(ptr::null(), errbuf.as_mut_ptr() as *mut _),
                Some(path) => {
                    let path = CString::new(path).or(Err(Error::InvalidString))?;
                    func(path.as_ptr(), errbuf.as_mut_ptr() as *mut _)
                },
            };
            if handle.is_null() {
                Error::new(errbuf.as_ptr() as *const _)
            } else {
                Ok(Capture {
                    handle: Unique::new(handle),
                    _marker: PhantomData,
                })
            }
        }
    }
}

impl Capture<Offline> {
    /// Opens an offline capture handle from a pcap dump file, given a path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Capture<Offline>, Error> {
        Capture::new_raw(path.as_ref().to_str(), |path, err| unsafe {
            raw::pcap_open_offline(path, err)
        })
    }

    /// Opens an offline capture handle from a pcap dump file, given a path.
    /// Takes an additional precision argument specifying the time stamp precision desired.
    pub fn from_file_with_precision<P: AsRef<Path>>(path: P, precision: Precision) -> Result<Capture<Offline>, Error> {
        Capture::new_raw(path.as_ref().to_str(), |path, err| unsafe {
            raw::pcap_open_offline_with_tstamp_precision(path, precision as u8 as _, err)
        })
    }

    /// Opens an offline capture handle from a pcap dump file, given a file descriptor.
    #[cfg(not(windows))]
    pub fn from_raw_fd(fd: RawFd) -> Result<Capture<Offline>, Error> {
        const MODE: [u8; 2] = [b'r', 0];

        let file = unsafe { libc::fdopen(fd, MODE.as_ptr() as *const _) };
        if file.is_null() {
             Err(Error::InvalidRawFd)
        } else {
            Capture::new_raw(None, |_, err| unsafe {
                raw::pcap_fopen_offline(file, err)
            })
        }
    }

    /// Opens an offline capture handle from a pcap dump file, given a file descriptor.
    /// Takes an additional precision argument specifying the time stamp precision desired.
    #[cfg(all(not(windows), feature = "pcap-fopen-offline-precision"))]
    pub fn from_raw_fd_with_precision(fd: RawFd, precision: Precision) -> Result<Capture<Offline>, Error> {
        const MODE: [u8; 2] = [b'r', 0];

        // File handle will be closed by libpcap.
        let file = unsafe { libc::fdopen(fd, MODE.as_ptr() as *const _) };
        if file.is_null() {
            return Err(Error::InvalidRawFd);
        } else {
            Capture::new_raw(None, |_, err| unsafe {
                raw::pcap_fopen_offline_with_tstamp_precision(file, precision as u8 as _, err)
            })
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TimestampType {
    Host = 0,
    HostLowPrec = 1,
    HostHighPrec = 2,
    Adapter = 3,
    AdapterUnsynced = 4,
}

#[deprecated(note = "Renamed to TimestampType")]
pub type TstampType = TimestampType;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Direction {
    InOut,
    In,
    Out,
}

impl Capture<Inactive> {
    /// Opens a capture handle for a device. You can pass a `Device` or an `&str` device
    /// name here. The handle is inactive, but can be activated via `.open()`.
    pub fn from_device<D: Into<Device>>(device: D) -> Result<Capture<Inactive>, Error> {
        let device: Device = device.into();
        Capture::new_raw(Some(&device.name), |name, err| unsafe {
            raw::pcap_create(name, err)
        })
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

    /// Set the time stamp type to be used by a capture device.
    #[cfg(not(windows))]
    pub fn tstamp_type(self, tstamp_type: TimestampType) -> Capture<Inactive> {
        unsafe {
            raw::pcap_set_tstamp_type(*self.handle, tstamp_type as u8 as _);
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
    ///
    /// **This is not available on Windows.**
    #[cfg(not(target_os = "windows"))]
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

    /// Set the time stamp precision returned in captures.
    #[cfg(not(windows))]
    pub fn precision(self, precision: Precision) -> Capture<Inactive> {
        unsafe {
            raw::pcap_set_tstamp_precision(*self.handle, precision as u8 as _);
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
impl<T: Activated + ?Sized> Capture<T> {
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

    /// Create a `Savefile` context for recording captured packets using this `Capture`'s
    /// configurations. The output is written to a raw file descriptor which is opened
    // in `"w"` mode.
    #[cfg(not(windows))]
    pub fn savefile_raw_fd(&self, fd: RawFd) -> Result<Savefile, Error> {
        const MODE: [u8; 2] = [b'w', 0];

        unsafe {
            // File handle will be closed by libpcap.
            let file: *mut _ = libc::fdopen(fd, MODE.as_ptr() as *const _);
            if file.is_null() {
                return Err(Error::InvalidRawFd);
            }

            let handle = raw::pcap_dump_fopen(*self.handle, file);
            if handle.is_null() {
                Error::new(raw::pcap_geterr(*self.handle))
            } else {
                Ok(Savefile {
                    handle: Unique::new(handle)
                })
            }
        }
    }

    /// Reopen a `Savefile` context for recording captured packets using this `Capture`'s
    /// configurations. This is similar to `savefile()` but does not create the file if it
    /// does  not exist and, if it does already exist, and is a pcap file with the same
    /// byte order as the host opening the file, and has the same time stamp precision,
    /// link-layer header type,  and  snapshot length as p, it will write new packets
    /// at the end of the file.
    #[cfg(feature = "pcap-savefile-append")]
    pub fn savefile_append<P: AsRef<Path>>(&self, path: P) -> Result<Savefile, Error> {
        let name = CString::new(path.as_ref().to_str().unwrap()).unwrap();
        unsafe {
            let handle = raw::pcap_dump_open_append(*self.handle, name.as_ptr());

            if handle.is_null() {
                Error::new(raw::pcap_geterr(*self.handle))
            } else {
                Ok(Savefile {
                    handle: Unique::new(handle)
                })
            }
        }
    }

    /// Set the direction of the capture
    pub fn direction(&self, direction: Direction) -> Result<(), Error> {
        let result = unsafe {
            raw::pcap_setdirection(*self.handle, match direction {
                Direction::InOut => raw::PCAP_D_INOUT,
                Direction::In => raw::PCAP_D_IN,
                Direction::Out => raw::PCAP_D_OUT,
            })
        };
        if result == 0 {
            Ok(())
        } else {
            Error::new( unsafe { raw::pcap_geterr(*self.handle) })
        }
    }

    /// Blocks until a packet is returned from the capture handle or an error occurs.
    ///
    /// pcap captures packets and places them into a buffer which this function reads
    /// from. This buffer has a finite length, so if the buffer fills completely new
    /// packets will be discarded temporarily. This means that in realtime situations,
    /// you probably want to minimize the time between calls of this next() method.
    pub fn next<'a>(&'a mut self) -> Result<Packet<'a>, Error> {
        unsafe {
            let mut header: *mut raw::Struct_pcap_pkthdr = ptr::null_mut();
            let mut packet: *const libc::c_uchar = ptr::null();
            match raw::pcap_next_ex(*self.handle, &mut header, &mut packet) {
                i if i >= 1 => {
                    // packet was read without issue
                    Ok(Packet {
                        header: transmute(&*header),
                        data: slice::from_raw_parts(packet, (&*header).caplen as usize)
                    })
                },
                0 => {
                    // packets are being read from a live capture and the
                    // timeout expired
                    Err(TimeoutExpired)
                },
                -1 => {
                    // an error occured while reading the packet
                    Error::new(raw::pcap_geterr(*self.handle))
                },
                -2 => {
                    // packets are being read from a "savefile" and there are no
                    // more packets to read
                    Err(NoMorePackets)
                },
                _ => {
                    // libpcap only defines codes >=1, 0, -1, and -2
                    unreachable!()
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

    pub fn stats(&mut self) -> Result<Stat, Error> {
        unsafe {
            let mut stats: raw::Struct_pcap_stat =
                raw::Struct_pcap_stat {ps_recv: 0, ps_drop: 0, ps_ifdrop: 0};

            if -1 == raw::pcap_stats(*self.handle, &mut stats) {
                return Error::new(raw::pcap_geterr(*self.handle));
            }

            Ok(Stat {
                received: stats.ps_recv,
                dropped: stats.ps_drop,
                if_dropped: stats.ps_ifdrop
            })
        }
    }
}

impl Capture<Active> {
    /// Sends a packet over this capture handle's interface.
    pub fn sendpacket<'a>(&mut self, buf: &'a [u8]) -> Result<(), Error> {
        unsafe {
            let result = raw::pcap_sendpacket(*self.handle, buf.as_ptr() as *const _, buf.len() as i32);

            match result {
                -1 => {
                    return Error::new(raw::pcap_geterr(*self.handle));
                },
                _ => {
                    Ok(())
                }
            }
        }
    }
}

impl Capture<Dead> {
    /// Creates a "fake" capture handle for the given link type.
    pub fn dead(linktype: Linktype) -> Result<Capture<Dead>, Error> {
        unsafe {
            let handle = raw::pcap_open_dead(linktype.0, 65535);
            if handle.is_null() {
                return Err(Error::InsufficientMemory);
            }

            Ok(Capture {
                handle: Unique::new(handle),
                _marker: PhantomData
            })
        }
    }
}

#[cfg(not(windows))]
impl AsRawFd for Capture<Active> {
    fn as_raw_fd(&self) -> RawFd {
        unsafe {
            let fd = raw::pcap_fileno(*self.handle);

            match fd {
                -1 => {
                    panic!("Unable to get file descriptor for live capture");
                },
                fd => {
                    fd
                }
            }
        }
    }
}

impl<T: State + ?Sized> Drop for Capture<T> {
    fn drop(&mut self) {
        unsafe {
            raw::pcap_close(*self.handle)
        }
    }
}

impl<T: Activated> From<Capture<T>> for Capture<Activated> {
    fn from(cap: Capture<T>) -> Capture<Activated> {
        unsafe { transmute(cap) }
    }
}

/// Abstraction for writing pcap savefiles, which can be read afterwards via `Capture::from_file()`.
pub struct Savefile {
    handle: Unique<raw::pcap_dumper_t>
}

impl Savefile {
    pub fn write<'a>(&mut self, packet: &'a Packet<'a>) {
        unsafe {
            raw::pcap_dump(*self.handle as *mut u8, transmute::<_, &raw::Struct_pcap_pkthdr>(packet.header), packet.data.as_ptr());
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
