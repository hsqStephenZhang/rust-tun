//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use std::{ffi, io, num};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid configuration")]
    InvalidConfig,

    #[error("not implementated")]
    NotImplemented,

    #[error("device name too long")]
    NameTooLong,

    #[error("invalid device name")]
    InvalidName,

    #[error("invalid address")]
    InvalidAddress,

    #[error("invalid file descriptor")]
    InvalidDescriptor,

    #[error("unsuported network layer of operation")]
    UnsupportedLayer,

    #[error("invalid queues number")]
    InvalidQueuesNumber,

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Nul(#[from] ffi::NulError),

    #[error(transparent)]
    ParseNum(#[from] num::ParseIntError),

    #[cfg(feature = "offload")]
    #[error("vnet_hdr error")]
    VnetHdr,

    #[cfg(feature = "offload")]
    #[error("buffer too small")]
    BufferTooSmall,

    #[cfg(feature = "offload")]
    #[error("offload flow not found")]
    OffloadFlowNotFound,

    #[cfg(feature = "offload")]
    #[error("offload item invalid checksum")]
    OffloadItemInvalidChecksum,

    #[cfg(feature = "offload")]
    #[error("offload packet invalid checksum")]
    OffloadPacketInvalidChecksum,

    #[cfg(feature = "offload")]
    #[error("offload TCP PSH flag set")]
    OffloadTcpPshFlagSet,

    #[cfg(target_os = "windows")]
    #[error(transparent)]
    WintunError(#[from] wintun::Error),
}

pub type Result<T, E = Error> = ::std::result::Result<T, E>;
