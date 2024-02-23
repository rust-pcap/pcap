use std::{ffi::CString, fmt, mem, ptr::NonNull, slice};

use crate::{
    core::{
        capture::{Capture, Dead},
        linktype::Linktype,
    },
    raw, Error,
};

#[cfg(libpcap_1_5_0)]
use crate::core::capture::Precision;

impl Capture<Dead> {
    /// Creates a "fake" capture handle for the given link type.
    pub fn dead(linktype: Linktype) -> Result<Capture<Dead>, Error> {
        let handle = unsafe { raw::pcap_open_dead(linktype.0, 65535) };
        Ok(Capture::from(
            NonNull::<raw::pcap_t>::new(handle).ok_or(Error::InsufficientMemory)?,
        ))
    }

    /// Creates a "fake" capture handle for the given link type and timestamp precision.
    #[cfg(libpcap_1_5_0)]
    pub fn dead_with_precision(
        linktype: Linktype,
        precision: Precision,
    ) -> Result<Capture<Dead>, Error> {
        let handle = unsafe {
            raw::pcap_open_dead_with_tstamp_precision(linktype.0, 65535, precision as u32)
        };
        Ok(Capture::from(
            NonNull::<raw::pcap_t>::new(handle).ok_or(Error::InsufficientMemory)?,
        ))
    }

    /// Compiles the string into a filter program using `pcap_compile`.
    pub fn compile(&self, program: &str, optimize: bool) -> Result<BpfProgram, Error> {
        let program = CString::new(program).unwrap();

        unsafe {
            let mut bpf_program: raw::bpf_program = mem::zeroed();
            if -1
                == raw::pcap_compile(
                    self.handle.as_ptr(),
                    &mut bpf_program,
                    program.as_ptr(),
                    optimize as libc::c_int,
                    0,
                )
            {
                return Err(Error::new(raw::pcap_geterr(self.handle.as_ptr())));
            }
            Ok(BpfProgram(bpf_program))
        }
    }
}

#[repr(transparent)]
pub struct BpfInstruction(raw::bpf_insn);
#[repr(transparent)]
pub struct BpfProgram(raw::bpf_program);

impl BpfProgram {
    /// checks whether a filter matches a packet
    pub fn filter(&self, buf: &[u8]) -> bool {
        let header: raw::pcap_pkthdr = raw::pcap_pkthdr {
            ts: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: buf.len() as u32,
            len: buf.len() as u32,
        };
        unsafe { raw::pcap_offline_filter(&self.0, &header, buf.as_ptr()) > 0 }
    }

    pub fn get_instructions(&self) -> &[BpfInstruction] {
        unsafe {
            slice::from_raw_parts(
                self.0.bf_insns as *const BpfInstruction,
                self.0.bf_len as usize,
            )
        }
    }
}

impl Drop for BpfProgram {
    fn drop(&mut self) {
        unsafe { raw::pcap_freecode(&mut self.0) }
    }
}

impl fmt::Display for BpfInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.0.code, self.0.jt, self.0.jf, self.0.k
        )
    }
}

unsafe impl Send for BpfProgram {}
