use std::env;
use std::ffi::CStr;
use std::os::raw::c_char;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Version {
    major: usize,
    minor: usize,
    micro: usize,
}

impl Version {
    fn new(major: usize, minor: usize, micro: usize) -> Version {
        Version {
            major,
            minor,
            micro,
        }
    }
}

fn get_pcap_lib_version() -> Result<Version, Box<dyn std::error::Error>> {
    #[cfg(all(unix, not(target_os = "macos")))]
    let libfile = "libpcap.so";
    #[cfg(target_os = "macos")]
    let libfile = "libpcap.dylib";
    #[cfg(windows)]
    let libfile = "wpcap.dll";

    let lib = libloading::Library::new(libfile)?;

    type PcapLibVersion = unsafe extern "C" fn() -> *mut c_char;
    let pcap_lib_version = unsafe { lib.get::<PcapLibVersion>(b"pcap_lib_version")? };

    let c_buf: *const c_char = unsafe { pcap_lib_version() };
    let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
    let v_str: &str = c_str.to_str()?;

    let err = format!("cannot infer pcap lib version from: {}", v_str);

    #[cfg(not(windows))]
    {
        let re = regex::Regex::new(r"libpcap version ([[:digit:]]+)\.([[:digit:]]+)\.([[:digit:]]+)")?;
        let captures = re.captures(v_str).ok_or(err.clone())?;

        let major_str = captures.get(1).ok_or(err.clone())?.as_str();
        let minor_str = captures.get(2).ok_or(err.clone())?.as_str();
        let micro_str = captures.get(3).ok_or(err.clone())?.as_str();

        Ok(Version::new(
            major_str.parse::<usize>()?,
            minor_str.parse::<usize>()?,
            micro_str.parse::<usize>()?,
        ))
    }

    #[cfg(windows)]
    {
        let re = regex::Regex::new(r"based on libpcap version ([[:digit:]]+)\.([[:digit:]]+)")?;
        let captures = re.captures(v_str).ok_or(err.clone())?;

        let major_str = captures.get(1).ok_or(err.clone())?.as_str();
        let minor_str = captures.get(2).ok_or(err.clone())?.as_str();

        Ok(Version::new(
            major_str.parse::<usize>()?,
            minor_str.parse::<usize>()?,
            0,
        ))
    }
}

fn emit_cfg_flags(version: Version) {
    assert!(
        version >= Version::new(1, 0, 0),
        "required pcap lib version: >=1.0.0"
    );
    let api_vers: Vec<Version> = vec![
        Version::new(1, 2, 1),
        Version::new(1, 5, 0),
        Version::new(1, 7, 2),
        Version::new(1, 9, 0),
        Version::new(1, 9, 1),
    ];

    for v in api_vers.iter().filter(|&v| v <= &version) {
        println!("cargo:rustc-cfg=pcap_{}_{}_{}", v.major, v.minor, v.micro);
    }
}

fn main() {
    if let Ok(libdir) = env::var("PCAP_LIBDIR") {
        println!("cargo:rustc-link-search=native={}", libdir);
    }

    let version = get_pcap_lib_version().unwrap();
    emit_cfg_flags(version);
}
