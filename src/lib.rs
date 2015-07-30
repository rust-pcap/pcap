extern crate libc;

use unique::Unique;
use std::marker::PhantomData;
use std::ptr::{self};
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

impl Device {
    /// Returns the default Device suitable for captures according to pcap_lookupdev,
    /// or an error from pcap.
    pub fn lookup() -> Result<Device, Error> {
        let mut errbuf = [0i8; 256];

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
}

impl<'a> Into<Device> for &'a str {
    fn into(self) -> Device {
        Device {
            name: self.into(),
            desc: None
        }
    }
}

/// This is a datalink link type returned from pcap.
#[derive(Debug)]
pub struct Linktype(pub i32);

impl Linktype {
    /// Gets the name of the link type, such as EN10MB
    pub fn get_name(&self) -> Result<String, Error> {
        unsafe {
            Ok(try!(cstr_to_string(raw::pcap_datalink_val_to_name(self.0))))
        }
    }

    /// Gets the description of a link type.
    pub fn get_description(&self) -> Result<String, Error> {
        unsafe {
            Ok(try!(cstr_to_string(raw::pcap_datalink_val_to_description(self.0))))
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

    fn deref<'a>(&'a self) -> &'a [u8] {
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
/// Phantom type representing an active capture handle. Implements `Activated`.
pub enum Active {}
/// Phantom type representing an offline capture handle, from a pcap dump file.
/// Implements `Activated`.
pub enum Offline {}

trait Activated {}

impl Activated for Active {}
impl Activated for Offline {}

/// This is a capture handle which is internally represented by `pcap_t`. This handle uses
/// a phantom type (Inactive, Active, Offline) to represent the kind of handle it is currently.
///
/// MORE DOCS HERE!
pub struct Capture<T> {
    handle: Unique<raw::pcap_t>,
    _marker: PhantomData<T>
}

impl Capture<Inactive> {
    /// Opens a capture handle for a device. The handle is inactive, but can be activated
    /// via `.open()`.
    pub fn from_device<D: Into<Device>>(device: D) -> Result<Capture<Inactive>, Error> {
        let device: Device = device.into();
        let name = CString::new(device.name).unwrap();
        let mut errbuf = [0i8; 256];

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

impl Capture<Offline> {
    /// Opens an offline capture handle from a pcap dump file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Capture<Offline>, Error> {
        let name = CString::new(path.as_ref().to_str().unwrap()).unwrap();
        let mut errbuf = [0i8; 256];

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

////# Activated captures include `Capture<Active>` and `Capture<Offline>`.
impl<T: Activated> Capture<T> {
    /// List the datalink types that this captured device supports.
    pub fn list_datalinks(&mut self) -> Result<Vec<Linktype>, Error> {
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
    pub fn get_datalink(&mut self) -> Linktype {
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

impl<T> Drop for Capture<T> {
    fn drop(&mut self) {
        unsafe {
            raw::pcap_close(*self.handle)
        }
    }
}

fn cstr_to_string(ptr: *const libc::c_char) -> Result<String, str::Utf8Error> {
    Ok(try!(str::from_utf8(unsafe{CStr::from_ptr(ptr)}.to_bytes())).to_string())
}
