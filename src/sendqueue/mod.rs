#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows::{SendQueue, SendSync};
