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
    const LOWEST_SUPPORTED: Self = Self {
        major: 1,
        minor: 0,
        micro: 0,
    };

    fn new(major: usize, minor: usize, micro: usize) -> Version {
        Version {
            major,
            minor,
            micro,
        }
    }

    fn list() -> Vec<Version> {
        vec![
            Version::new(1, 2, 1),
            Version::new(1, 5, 0),
            Version::new(1, 5, 3),
            Version::new(1, 7, 2),
            Version::new(1, 9, 0),
            Version::new(1, 9, 1),
            Version::new(1, 10, 0),
        ]
    }

    fn max() -> Version {
        #[cfg(not(windows))]
        {
            Version::new(1, 9, 1)
        }
        #[cfg(windows)]
        {
            Version::new(1, 0, 0)
        }
    }

    fn docs_rs() -> Version {
        Version::new(2, 0, 0)
    }

    fn parse(s: &str) -> Result<Version, Box<dyn std::error::Error>> {
        let err = format!("invalid pcap lib version: {s}");

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

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Version {
            major,
            minor,
            micro,
        } = self;
        write!(f, "{major}.{minor}.{micro}")
    }
}

fn get_libpcap_version(libdirpath: Option<PathBuf>) -> Result<Version, Box<dyn std::error::Error>> {
    if std::env::var("DOCS_RS").is_ok() {
        return Ok(Version::docs_rs());
    }

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

    // Loading a shared library is unsafe in the general case since initialization and termination
    // routines could have arbitrary behavior. This is sound as long as the shared library is
    // "well-behaved." See https://github.com/nagisa/rust_libloading/issues/86 and
    // https://github.com/nagisa/rust_libloading/blob/0.8.3/src/changelog.rs#L96-L151 for details.
    let lib = unsafe { libloading::Library::new(libfile) };

    // On Windows LIBPCAP_LIBDIR names the directory holding wpcap.lib, and the Npcap SDK does not
    // ship wpcap.dll beside it, so not finding the library there says nothing about the version in
    // use. Ask the loader for it by name, the way the crate being built will get at it.
    #[cfg(windows)]
    let lib = lib.or_else(|_| unsafe { libloading::Library::new("wpcap.dll") });

    let Ok(lib) = lib else {
        // Falling back compiles out every version gated binding, which from the outside looks
        // like the crate not having them rather than like a library that could not be found.
        let version = Version::max();
        println!(
            "cargo:warning=no pcap library was found to read a version from, so the bindings \
             added after {}.{}.{} are being compiled out",
            version.major, version.minor, version.micro
        );
        return Ok(version);
    };

    type PcapLibVersion = unsafe extern "C" fn() -> *mut c_char;
    let pcap_lib_version = unsafe { lib.get::<PcapLibVersion>(b"pcap_lib_version")? };

    let c_buf: *const c_char = unsafe { pcap_lib_version() };
    let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
    let v_str: &str = c_str.to_str()?;

    let err = format!("cannot infer pcap lib version from: {v_str}");

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
        version >= Version::LOWEST_SUPPORTED,
        "required pcap lib version: >=1.0.0"
    );

    for v in Version::list().iter() {
        println!(
            "cargo:rustc-check-cfg=cfg(libpcap_{}_{}_{})",
            v.major, v.minor, v.micro
        );
        if v <= &version {
            println!(
                "cargo:rustc-cfg=libpcap_{}_{}_{}",
                v.major, v.minor, v.micro
            );
        }
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=LIBPCAP_LIBDIR");
    println!("cargo:rerun-if-env-changed=LIBPCAP_VER");

    // If user explicitly set LIBPCAP_LIBDIR, honour their wishes. This keeps
    // existing build scripts running. If it's not set, try pkg-config. If
    // that's not set, try last ditch effort to build even though library wasn't
    // explicitly given.
    let version = if let Ok(libdir) = env::var("LIBPCAP_LIBDIR") {
        println!("cargo:rustc-link-search=native={libdir}");
        get_libpcap_version(Some(PathBuf::from(&libdir))).unwrap()
    } else if let Ok(library) = from_pkg_config() {
        Version::parse(&library.version).unwrap()
    } else {
        get_libpcap_version(None).unwrap()
    };

    emit_cfg_flags(version);
}

fn from_pkg_config() -> Result<pkg_config::Library, pkg_config::Error> {
    let mut config = pkg_config::Config::new();
    // If the user has went out of their way to specify LIBPCAP_VER (even though
    // LIBCAP_LIBDIR wasn't set), respect it. Otherwise fall back to any version
    // as long as it's supported.
    if let Ok(v) = env::var("LIBPCAP_VER") {
        config.exactly_version(&v);
    } else {
        config.atleast_version(&Version::LOWEST_SUPPORTED.to_string());
    };
    config.probe("libpcap")
}
