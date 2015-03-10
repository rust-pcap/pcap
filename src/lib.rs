#![feature(libc, int_uint, core, unique)]

extern crate libc;

use std::ptr::{self, Unique};
use std::ffi::{CStr,CString};
use std::default::Default;
use std::mem::transmute;
use std::slice::SliceExt;
use std::raw::Slice;
use std::ops::Deref;
use std::str;
mod raw;

/// An iterator over devices that pcap is aware about on the system.
pub struct Devices {
    orig: Unique<raw::Struct_pcap_if>,
    device: Unique<raw::Struct_pcap_if>
}

impl Devices {
    /// Construct a new `Devices` iterator by internally using `pcap_findalldevs()`
    pub fn list_all() -> Result<Devices, String> {
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
                    Err(
                        cstr_to_string(errbuf.as_ptr()).unwrap()
                    )
                }
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
/// A network device as constructed with `Device::new()` or returned from `Devices::list_all()`.
pub struct Device {
    pub name: String,
    pub desc: Option<String>
}

impl Device {
    /// Create a new device with a given name, useful when you know the name of the device already.
    pub fn new(name: &str) -> Device {
        Device {
            name: name.to_string(),
            desc: None
        }
    }

    /// Open a `Capture` for this network device.
    pub fn open(&self) -> Result<Capture, String> {
        let name = CString::new(&self.name[..]).unwrap();
        let mut errbuf = [0i8; 256];

        unsafe {
            let pcap_t = raw::pcap_open_live(name.as_ptr(), 65535, 1, 0, errbuf.as_mut_ptr());
            if pcap_t.is_null() {
                Err(
                    cstr_to_string(errbuf.as_ptr()).unwrap()
                )
            } else {
                Ok(Capture{
                    handle: Unique::new(pcap_t)
                })
            }
        }
    }
}

/// A packet obtained from a `Capture`.
///
/// This can be dereferenced to access the raw packet data.
pub enum Packet<'a> {
    Allocated(Vec<u8>),
    Borrowed(&'a [u8])
}

impl<'b> Deref for Packet<'b> {
    type Target = [u8];

    fn deref<'a>(&'a self) -> &'a [u8] {
        match *self {
            Packet::Allocated(ref v) => {
                v.as_slice()
            },
            Packet::Borrowed(x) => x
        }
    }
}

/// An iterator over packets obtained from a `Capture` in realtime.
///
/// This iterator will allocate a `Vec<u8>` for each packet it receives. If this
/// is not tolerable, try using `.next()` on `Capture` directly instead of this
/// iterator.
pub struct Packets<'a> {
    capture: &'a mut Capture
}

impl<'a, 'b> Iterator for Packets<'a> {
    type Item = Packet<'b>;

    fn next(&mut self) -> Option<Packet> {
        self.capture.next().map(|x| Packet::Allocated((*x).to_vec()))
    }
}

/// This represents an open capture handle obtained by calling `.open()` on a `Device`.
/// Internally it represents a `pcap_t` handle obtained by `pcap_open_live()`.
pub struct Capture {
    handle: Unique<raw::pcap_t>
}

impl Capture {
    /// Returns an iterator over packets received on this capture handle.
    pub fn listen<'a>(&'a mut self) -> Packets<'a> {
        Packets {
            capture: self
        }
    }

    /// Blocks until a packet is returned from the capture handle or an error occurs.
    pub fn next<'a>(&'a mut self) -> Option<Packet<'a>> {
        unsafe {
            let mut header: *mut raw::Struct_pcap_pkthdr = ptr::null_mut();
            let mut packet: *const libc::c_uchar = ptr::null_mut();
            match raw::pcap_next_ex(*self.handle, &mut header, &mut packet) {
                1 => {
                    // packet was read without issue
                    let packet = transmute::<_, &[u8]>(Slice {
                        data: packet,
                        len: (*header).len as usize
                    });

                    Some(Packet::Borrowed(packet))
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
    pub fn filter(&mut self, program: &str) -> Result<(), String> {
        let program = CString::new(program).unwrap();

        unsafe {
            let mut bpf_program: raw::Struct_bpf_program = Default::default();

            if -1 == raw::pcap_compile(*self.handle, &mut bpf_program, program.as_ptr(), 0, 0) {
                return Err(cstr_to_string(raw::pcap_geterr(*self.handle)).unwrap());
            }

            if -1 == raw::pcap_setfilter(*self.handle, &mut bpf_program) {
                raw::pcap_freecode(&mut bpf_program);
                return Err(cstr_to_string(raw::pcap_geterr(*self.handle)).unwrap());
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

fn cstr_to_string(ptr: *const libc::c_char) -> Result<String, str::Utf8Error> {
    Ok(try!(str::from_utf8(unsafe{CStr::from_ptr(ptr)}.to_bytes())).to_string())
}