# Changelog

## [Unreleased]

### Added

 - [doc](https://docs.rs/pcap/latest/pcap/) will now include all features
 - Add support for sendqueues on Windows.
 - Add `PacketStream::inner_mut` to still be able to inject packets when using `PacketStream`

### Changed

- `Device::lookup` now returns `Result<Option<Device>, Error>` rather than `Result<Device, Error>`. `Ok(None)` means that the lookup succeeded, but no suitable devices were available. This is consistent with libpcap.
- `Capture` and `Savefile` no longer implement the `Sync` trait. The underlying `libpcap` library does not promise thread-safe access for the same capture object from multiple threads.
- Switched from `winapi` to `windows-sys` for Windows builds.  `windows-sys` requires rustc 1.46.0.

### Removed

- `docs-rs` feature
- `full` feature
- `stream::SelectableFd` and `stream::PacketStream::new` as they were only meant to be used internally

## [0.9.2] - 2022-04-15

### Changed

- `capture-stream` requires rustc version 1.49.0 due to dependency on `tokio`.

## [0.9.1] - 2021-11-07

### Added

- Add support for device addresses.

## [0.9.0] - 2021-09-05

### Added

- Add `savefile.flush` support.

### Changed

- Updated dependency `tokio` from version 0.2 to 1.0
- `capture-stream` requires rustc version 1.45.0 due to dependency on `tokio`.

## [0.8.1] - 2020-12-30

### Changed

- Fix docs.rs build.

## [0.8.0] - 2020-12-30

### Added

- Add `Derive(Clone)` to `Device` struct (#100).
- Build-time `libpcap` version detection.
- Add support for immediate mode.
- Add const value for Linktype (#145)
- Add support for BPF compile

### Changed

- Opt into Rust 2018.
- Now minimum supported rustc version is 1.40.0.
- Updated dependency from deprecated `tokio-core` to `tokio` 0.2.
- Updated dependency `futures` from version 0.1 to 0.3.
- Feature `tokio` renamed to `capture-stream` because Cargo does not allow
  features and dependencies to have the same name.
- `PCAP_LIBDIR` renamed to `LIBPCAP_LIBDIR` to distinguish the `pcap` crate
  from the `libpcap` library.
- All methods that construct objects out of a `RawFd` are now unsafe.
- All methods that take a raw pointer are now unsafe. Some of these functions
  were renamed from `new` to `from_handle` to underline this.

### Removed

- Feature flags `pcap-savefile-append`, `pcap-fopen-offline-precision`
  (replaced by build-time `libpcap` version detection)

## [0.7.0] - 2017-08-04

No Changelog entries for <= 0.7.0
