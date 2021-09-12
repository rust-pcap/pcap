use std::env;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;

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

    fn parse(s: &str) -> Result<Version, Box<dyn std::error::Error>> {
        let err = format!("invalid pcap lib version: {}", s);

        let re = regex::Regex::new(r"([[:digit:]]+)\.([[:digit:]]+)\.([[:digit:]]+)")?;
        let captures = re.captures(s).ok_or_else(|| err.clone())?;

        let major_str = captures.get(1).ok_or_else(|| err.clone())?.as_str();
        let minor_str = captures.get(2).ok_or_else(|| err.clone())?.as_str();
        let micro_str = captures.get(3).ok_or_else(|| err.clone())?.as_str();

        Ok(Version::new(
            major_str.parse::<usize>()?,
            minor_str.parse::<usize>()?,
            micro_str.parse::<usize>()?,
        ))
    }
}

fn get_pcap_lib_version(
    libdirpath: Option<PathBuf>,
) -> Result<Version, Box<dyn std::error::Error>> {
    #[cfg(feature = "docs-rs")]
    return Ok(Version {
        major: 2,
        minor: 0,
        micro: 0,
    });

    if let Ok(libver) = env::var("LIBPCAP_VER") {
        return Version::parse(&libver);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    let mut libfile = PathBuf::from("libpcap.so");
    #[cfg(target_os = "macos")]
    let mut libfile = PathBuf::from("libpcap.dylib");
    #[cfg(windows)]
    let mut libfile = PathBuf::from("wpcap.dll");

    if let Some(libdir) = libdirpath {
        libfile = libdir.join(libfile);
    }

    let lib = libloading::Library::new(libfile)?;

    type PcapLibVersion = unsafe extern "C" fn() -> *mut c_char;
    let pcap_lib_version = unsafe { lib.get::<PcapLibVersion>(b"pcap_lib_version")? };

    let c_buf: *const c_char = unsafe { pcap_lib_version() };
    let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
    let v_str: &str = c_str.to_str()?;

    let err = format!("cannot infer pcap lib version from: {}", v_str);

    #[cfg(not(windows))]
    {
        let re =
            regex::Regex::new(r"libpcap version ([[:digit:]]+)\.([[:digit:]]+)\.([[:digit:]]+)")?;
        let captures = re.captures(v_str).ok_or_else(|| err.clone())?;

        let major_str = captures.get(1).ok_or_else(|| err.clone())?.as_str();
        let minor_str = captures.get(2).ok_or_else(|| err.clone())?.as_str();
        let micro_str = captures.get(3).ok_or_else(|| err.clone())?.as_str();

        Ok(Version::new(
            major_str.parse::<usize>()?,
            minor_str.parse::<usize>()?,
            micro_str.parse::<usize>()?,
        ))
    }

    #[cfg(windows)]
    {
        let re = regex::Regex::new(r"based on libpcap version ([[:digit:]]+)\.([[:digit:]]+)")?;
        let captures = re.captures(v_str).ok_or_else(|| err.clone())?;

        let major_str = captures.get(1).ok_or_else(|| err.clone())?.as_str();
        let minor_str = captures.get(2).ok_or_else(|| err.clone())?.as_str();

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
        println!(
            "cargo:rustc-cfg=libpcap_{}_{}_{}",
            v.major, v.minor, v.micro
        );
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=LIBPCAP_LIBDIR");
    println!("cargo:rerun-if-env-changed=LIBPCAP_VER");

    let mut libdirpath: Option<PathBuf> = None;
    if let Ok(libdir) = env::var("LIBPCAP_LIBDIR") {
        println!("cargo:rustc-link-search=native={}", libdir);
        libdirpath = Some(PathBuf::from(&libdir));
    }

    let version = get_pcap_lib_version(libdirpath).unwrap();
    emit_cfg_flags(version);
}
