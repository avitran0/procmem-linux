use std::{io::Error, num::ParseIntError};

use thiserror::Error;

use crate::library::ParseLibraryError;

/// errors relating to the process struct.
#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("the requested process could not be found")]
    NotFound,
    #[error("the pid of the requested process is not valid")]
    InvalidPid(#[from] ParseIntError),
    #[error("unable to parse library")]
    InvalidLibrary(#[from] ParseLibraryError),
    #[error("misc io error")]
    Io(Error),
}

/// errors relating to memory reads/writes.
#[derive(Error, Debug)]
pub enum MemoryError {
    #[error("the requested address is out of range")]
    OutOfRange,
    #[error("the process has quit")]
    ProcessQuit,
    #[error("data could not be parsed to type {0}")]
    InvalidData(&'static str),
    #[error("only {0} out of {1} bytes could be transferred")]
    PartialTransfer(usize, usize),
    #[error("library at given address is not valid")]
    InvalidLibrary,
    #[error("c-style string was too long")]
    StringTooLong,
    #[error("string is not valid utf-8")]
    InvalidString,
    #[error("pattern was not found")]
    NotFound,
    #[error("misc io error")]
    Io(#[from] Error),
    #[error("unknown memory error")]
    Unknown,
}
