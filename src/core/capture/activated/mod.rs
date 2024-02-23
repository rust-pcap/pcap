pub mod active;
pub mod dead;
pub mod iterator;
pub mod offline;

use std::{
    ffi::CString,
    mem,
    path::Path,
    ptr::{self, NonNull},
    slice,
};

#[cfg(not(windows))]
use std::os::fd::RawFd;

use crate::{
    core::{
        capture::{Activated, Capture},
        codec::PacketCodec,
        linktype::Linktype,
        packet::{Packet, PacketHeader},
    },
    raw, Error,
};

use iterator::PacketIter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Packet statistics for a capture
pub struct Stat {
    /// Number of packets received
    pub received: u32,
    /// Number of packets dropped because there was no room in the operating system's buffer when
    /// they arrived, because packets weren't being read fast enough
    pub dropped: u32,
    /// Number of packets dropped by the network interface or its driver
    pub if_dropped: u32,
}

impl Stat {
    fn new(received: u32, dropped: u32, if_dropped: u32) -> Stat {
        Stat {
            received,
            dropped,
            if_dropped,
        }
    }
}

#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
/// The direction of packets to be captured. Use with `Capture::direction`.
pub enum Direction {
    /// Capture packets received by or sent by the device. This is the default.
    InOut = raw::PCAP_D_INOUT,
    /// Only capture packets received by the device.
    In = raw::PCAP_D_IN,
    /// Only capture packets sent by the device.
    Out = raw::PCAP_D_OUT,
}

///# Activated captures include `Capture<Active>` and `Capture<Offline>`.
impl<T: Activated + ?Sized> Capture<T> {
    /// List the datalink types that this captured device supports.
    pub fn list_datalinks(&self) -> Result<Vec<Linktype>, Error> {
        unsafe {
            let mut links: *mut i32 = ptr::null_mut();
            let num = raw::pcap_list_datalinks(self.handle.as_ptr(), &mut links);
            let mut vec = vec![];
            if num > 0 {
                vec.extend(
                    slice::from_raw_parts(links, num as _)
                        .iter()
                        .cloned()
                        .map(Linktype),
                )
            }
            raw::pcap_free_datalinks(links);
            self.check_err(num > 0).and(Ok(vec))
        }
    }

    /// Set the datalink type for the current capture handle.
    pub fn set_datalink(&mut self, linktype: Linktype) -> Result<(), Error> {
        self.check_err(unsafe { raw::pcap_set_datalink(self.handle.as_ptr(), linktype.0) == 0 })
    }

    /// Get the current datalink type for this capture handle.
    pub fn get_datalink(&self) -> Linktype {
        unsafe { Linktype(raw::pcap_datalink(self.handle.as_ptr())) }
    }

    /// Create a `Savefile` context for recording captured packets using this `Capture`'s
    /// configurations.
    pub fn savefile<P: AsRef<Path>>(&self, path: P) -> Result<Savefile, Error> {
        let name = CString::new(path.as_ref().to_str().unwrap())?;
        let handle_opt = NonNull::<raw::pcap_dumper_t>::new(unsafe {
            raw::pcap_dump_open(self.handle.as_ptr(), name.as_ptr())
        });
        let handle = self
            .check_err(handle_opt.is_some())
            .map(|_| handle_opt.unwrap())?;
        Ok(Savefile::from(handle))
    }

    /// Create a `Savefile` context for recording captured packets using this `Capture`'s
    /// configurations. The output is written to a raw file descriptor which is opened in `"w"`
    /// mode.
    ///
    /// # Safety
    ///
    /// Unsafe, because the returned Savefile assumes it is the sole owner of the file descriptor.
    #[cfg(not(windows))]
    pub unsafe fn savefile_raw_fd(&self, fd: RawFd) -> Result<Savefile, Error> {
        open_raw_fd(fd, b'w').and_then(|file| {
            let handle_opt = NonNull::<raw::pcap_dumper_t>::new(raw::pcap_dump_fopen(
                self.handle.as_ptr(),
                file,
            ));
            let handle = self
                .check_err(handle_opt.is_some())
                .map(|_| handle_opt.unwrap())?;
            Ok(Savefile::from(handle))
        })
    }

    /// Reopen a `Savefile` context for recording captured packets using this `Capture`'s
    /// configurations. This is similar to `savefile()` but does not create the file if it
    /// does  not exist and, if it does already exist, and is a pcap file with the same
    /// byte order as the host opening the file, and has the same time stamp precision,
    /// link-layer header type,  and  snapshot length as p, it will write new packets
    /// at the end of the file.
    #[cfg(libpcap_1_7_2)]
    pub fn savefile_append<P: AsRef<Path>>(&self, path: P) -> Result<Savefile, Error> {
        let name = CString::new(path.as_ref().to_str().unwrap())?;
        let handle_opt = NonNull::<raw::pcap_dumper_t>::new(unsafe {
            raw::pcap_dump_open_append(self.handle.as_ptr(), name.as_ptr())
        });
        let handle = self
            .check_err(handle_opt.is_some())
            .map(|_| handle_opt.unwrap())?;
        Ok(Savefile::from(handle))
    }

    /// Set the direction of the capture
    pub fn direction(&self, direction: Direction) -> Result<(), Error> {
        self.check_err(unsafe {
            raw::pcap_setdirection(self.handle.as_ptr(), direction as u32 as _) == 0
        })
    }

    /// Blocks until a packet is returned from the capture handle or an error occurs.
    ///
    /// pcap captures packets and places them into a buffer which this function reads
    /// from.
    ///
    /// # Warning
    ///
    /// This buffer has a finite length, so if the buffer fills completely new
    /// packets will be discarded temporarily. This means that in realtime situations,
    /// you probably want to minimize the time between calls to next_packet() method.
    pub fn next_packet(&mut self) -> Result<Packet<'_>, Error> {
        unsafe {
            let mut header: *mut raw::pcap_pkthdr = ptr::null_mut();
            let mut packet: *const libc::c_uchar = ptr::null();
            let retcode = raw::pcap_next_ex(self.handle.as_ptr(), &mut header, &mut packet);
            self.check_err(retcode != -1)?; // -1 => an error occured while reading the packet
            match retcode {
                i if i >= 1 => {
                    // packet was read without issue
                    Ok(Packet::new(
                        &*(&*header as *const raw::pcap_pkthdr as *const PacketHeader),
                        slice::from_raw_parts(packet, (*header).caplen as _),
                    ))
                }
                0 => {
                    // packets are being read from a live capture and the
                    // timeout expired
                    Err(Error::TimeoutExpired)
                }
                -2 => {
                    // packets are being read from a "savefile" and there are no
                    // more packets to read
                    Err(Error::NoMorePackets)
                }
                _ => {
                    // libpcap only defines codes >=1, 0, -1, and -2
                    unreachable!()
                }
            }
        }
    }

    /// Return an iterator that call [`Self::next_packet()`] forever. Require a [`PacketCodec`]
    pub fn iter<C: PacketCodec>(self, codec: C) -> PacketIter<T, C> {
        PacketIter::new(self, codec)
    }

    /// Sets the filter on the capture using the given BPF program string. Internally this is
    /// compiled using `pcap_compile()`. `optimize` controls whether optimization on the resulting
    /// code is performed
    ///
    /// See <http://biot.com/capstats/bpf.html> for more information about this syntax.
    pub fn filter(&mut self, program: &str, optimize: bool) -> Result<(), Error> {
        let program = CString::new(program)?;
        unsafe {
            let mut bpf_program: raw::bpf_program = mem::zeroed();
            let ret = raw::pcap_compile(
                self.handle.as_ptr(),
                &mut bpf_program,
                program.as_ptr(),
                optimize as libc::c_int,
                0,
            );
            self.check_err(ret != -1)?;
            let ret = raw::pcap_setfilter(self.handle.as_ptr(), &mut bpf_program);
            raw::pcap_freecode(&mut bpf_program);
            self.check_err(ret != -1)
        }
    }

    /// Get capture statistics about this capture. The values represent packet statistics from the
    /// start of the run to the time of the call.
    ///
    /// See <https://www.tcpdump.org/manpages/pcap_stats.3pcap.html> for per-platform caveats about
    /// how packet statistics are calculated.
    pub fn stats(&mut self) -> Result<Stat, Error> {
        unsafe {
            let mut stats: raw::pcap_stat = mem::zeroed();
            self.check_err(raw::pcap_stats(self.handle.as_ptr(), &mut stats) != -1)
                .map(|_| Stat::new(stats.ps_recv, stats.ps_drop, stats.ps_ifdrop))
        }
    }
}

impl<T: Activated> From<Capture<T>> for Capture<dyn Activated> {
    fn from(cap: Capture<T>) -> Capture<dyn Activated> {
        unsafe { mem::transmute(cap) }
    }
}

/// Abstraction for writing pcap savefiles, which can be read afterwards via `Capture::from_file()`.
pub struct Savefile {
    handle: NonNull<raw::pcap_dumper_t>,
}

// Just like a Capture, a Savefile is safe to Send as it encapsulates the entire lifetime of
// `raw::pcap_dumper_t *`, but it is not safe to Sync as libpcap does not promise thread-safe access
// to the same `raw::pcap_dumper_t *` from multiple threads.
unsafe impl Send for Savefile {}

impl Savefile {
    /// Write a packet to a capture file
    pub fn write(&mut self, packet: &Packet<'_>) {
        unsafe {
            raw::pcap_dump(
                self.handle.as_ptr() as _,
                &*(packet.header as *const PacketHeader as *const raw::pcap_pkthdr),
                packet.data.as_ptr(),
            );
        }
    }

    /// Flushes all the packets that haven't been written to the savefile
    pub fn flush(&mut self) -> Result<(), Error> {
        if unsafe { raw::pcap_dump_flush(self.handle.as_ptr() as _) } != 0 {
            return Err(Error::ErrnoError(errno::errno()));
        }

        Ok(())
    }
}

impl From<NonNull<raw::pcap_dumper_t>> for Savefile {
    fn from(handle: NonNull<raw::pcap_dumper_t>) -> Self {
        Savefile { handle }
    }
}

impl Drop for Savefile {
    fn drop(&mut self) {
        unsafe { raw::pcap_dump_close(self.handle.as_ptr()) }
    }
}

#[cfg(not(windows))]
/// Open a raw file descriptor.
///
/// # Safety
///
/// Unsafe, because the returned FILE assumes it is the sole owner of the file descriptor.
pub unsafe fn open_raw_fd(fd: RawFd, mode: u8) -> Result<*mut libc::FILE, Error> {
    let mode = [mode, 0];
    libc::fdopen(fd, mode.as_ptr() as _)
        .as_mut()
        .map(|f| f as _)
        .ok_or(Error::InvalidRawFd)
}
