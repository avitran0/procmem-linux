use std::num::IntErrorKind;

use thiserror::Error;

/// errors relating to the process struct.
#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("the requested process could not be found")]
    NotFound,
    #[error("the pid of the requested process is not valid")]
    InvalidPid(IntErrorKind),
    #[error("permission to open /proc/{0}/mem was denied")]
    PermissionDenied(i32),
    #[error("failed to open /proc/{0}/mem")]
    FileOpenError(i32),
}

/// errors relating to memory reads/writes.
#[derive(Error, Debug)]
pub enum MemoryError {
    #[error("the requested address is out of range")]
    OutOfRange,
    #[error("the process has quit")]
    ProcessQuit,
    #[error("permission to memory was denied")]
    PermissionDenied,
    #[error("data could not be parsed to type {0}")]
    InvalidData(&'static str),
    #[error("only {0} out of {1} bytes could be transferred")]
    PartialTransfer(usize, usize),
    #[error("library at given address is not valid")]
    LibraryNotValid,
    #[error("pattern was not found")]
    NotFound,
    #[error("unknown read error")]
    Unknown,
}