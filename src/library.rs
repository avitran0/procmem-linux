use std::{num::ParseIntError, str::FromStr};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParsePermError {
    #[error("permissions string must be 4 characters long, got {0}")]
    InvalidLength(String),
    #[error("invalid character \"{0}\" at position {1}")]
    InvalidChar(char, usize),
}

#[derive(Debug, Clone)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub private: bool,
}

impl FromStr for Permissions {
    type Err = ParsePermError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 4 {
            return Err(ParsePermError::InvalidLength(s.to_string()));
        }

        let bytes = s.as_bytes();

        let read = match bytes[0] {
            b'r' => true,
            b'-' => false,
            other => return Err(ParsePermError::InvalidChar(other as char, 0)),
        };
        let write = match bytes[1] {
            b'w' => true,
            b'-' => false,
            other => return Err(ParsePermError::InvalidChar(other as char, 1)),
        };
        let execute = match bytes[2] {
            b'x' => true,
            b'-' => false,
            other => return Err(ParsePermError::InvalidChar(other as char, 2)),
        };
        let private = match bytes[3] {
            b'p' => true,
            b's' => false,
            other => return Err(ParsePermError::InvalidChar(other as char, 3)),
        };

        Ok(Permissions {
            read,
            write,
            execute,
            private,
        })
    }
}

#[derive(Error, Debug)]
pub enum ParseLibraryError {
    #[error("expected at least 6 whitespace-separated fields, got {0}")]
    FieldCount(usize),
    #[error("address field was invalid")]
    InvalidAddress,
    #[error("permissions field was invalid")]
    InvalidPermissions(#[from] ParsePermError),
    #[error("offset field was invalid")]
    InvalidOffset(ParseIntError),
    #[error("inode field was invalid")]
    InvalidInode(ParseIntError),
}

#[derive(Debug, Clone)]
pub struct LibraryInfo {
    /// memory region start address
    start: usize,
    /// memory region end address
    end: usize,
    /// permissions of memory region
    permissions: Permissions,
    /// offset into mapped file
    offset: usize,
    /// device, in format `major:minor`
    device: String,
    inode: u64,
    /// can be a file path, special name like `[heap]`, or anonymous
    ///
    /// special names could be:
    ///
    /// - `[heap]`: process heap region
    /// - `[stack]`: the main threads' stack
    /// - `[vdso]`: virtual dynamic shared object
    /// - `[vsyscall]`: legacy syscall page
    /// - `[vvar]`: variable data page for vdso
    pathname: Option<String>,
}

impl LibraryInfo {
    pub fn start(&self) -> usize {
        self.start
    }

    pub fn end(&self) -> usize {
        self.end
    }

    pub fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn device(&self) -> &str {
        &self.device
    }

    pub fn inode(&self) -> u64 {
        self.inode
    }

    pub fn path(&self) -> Option<&str> {
        self.pathname.as_deref()
    }
}

impl FromStr for LibraryInfo {
    type Err = ParseLibraryError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // split into 6 fields: address range,
        // permissions, offset, device, inode and pathname
        let mut parts = s.splitn(6, char::is_whitespace).filter(|s| !s.is_empty());

        let address = parts.next().ok_or(ParseLibraryError::FieldCount(0))?;
        let permissions = parts.next().ok_or(ParseLibraryError::FieldCount(1))?;
        let offset = parts.next().ok_or(ParseLibraryError::FieldCount(2))?;
        let device = parts.next().ok_or(ParseLibraryError::FieldCount(3))?;
        let inode = parts.next().ok_or(ParseLibraryError::FieldCount(4))?;
        let path = parts.next();

        let Some((start, end)) = address.split_once('-') else {
            return Err(ParseLibraryError::InvalidAddress);
        };

        let start =
            usize::from_str_radix(start, 16).map_err(|_| ParseLibraryError::InvalidAddress)?;
        let end = usize::from_str_radix(end, 16).map_err(|_| ParseLibraryError::InvalidAddress)?;

        let permissions = permissions.parse()?;

        let offset = usize::from_str_radix(offset, 16).map_err(ParseLibraryError::InvalidOffset)?;
        let device = device.to_string();
        let inode = inode.parse().map_err(ParseLibraryError::InvalidInode)?;
        let pathname = path
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        Ok(Self {
            start,
            end,
            permissions,
            offset,
            device,
            inode,
            pathname,
        })
    }
}
