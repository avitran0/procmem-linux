use std::{
    fs::{File, OpenOptions, read_dir, read_link},
    io::{Error, ErrorKind},
    num::IntErrorKind,
    os::unix::fs::FileExt,
    path::Path,
};

use bytemuck::AnyBitPattern;
use libc::{EFAULT, EPERM, ESRCH, iovec, process_vm_readv};
use thiserror::Error;

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

#[derive(Error, Debug)]
pub enum ReadError {
    #[error("the requested address is out of range")]
    OutOfRange,
    #[error("the process has quit")]
    ProcessQuit,
    #[error("permission to read memory was denied")]
    PermissionDenied,
    #[error("data could not be parsed to type {0}")]
    InvalidData(&'static str),
    #[error("unknown read error")]
    Unknown,
}

pub struct Process {
    pid: i32,
    memory: Option<File>,
}

impl Process {
    fn find_pid(name: &str) -> Result<i32, ProcessError> {
        for dir in read_dir("/proc").unwrap() {
            let entry = match dir {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            match entry.file_type() {
                Ok(file_type) => {
                    if file_type.is_dir() {
                        continue;
                    }
                }
                Err(_) => continue,
            }

            let pid_osstr = entry.file_name();
            let pid = match pid_osstr.to_str() {
                Some(pid) => pid,
                None => continue,
            };

            if !pid.chars().all(|char| char.is_numeric()) {
                continue;
            }

            let Ok(exe_path) = read_link(format!("/proc/{}/exe", pid)) else {
                continue;
            };

            let exe_name = match exe_path.file_name() {
                Some(exe_name) => exe_name,
                None => continue,
            };

            if exe_name == name {
                let pid = match pid.parse::<i32>() {
                    Ok(pid) => pid,
                    Err(error) => return Err(ProcessError::InvalidPid(error.kind().clone())),
                };
                return Ok(pid);
            }
        }
        Err(ProcessError::NotFound)
    }

    pub fn open_name(name: &str) -> Result<Process, ProcessError> {
        let pid = Process::find_pid(name)?;
        Process::open_pid(pid)
    }

    pub fn open_pid(pid: i32) -> Result<Process, ProcessError> {
        // test whether process_vm_readv is a valid syscall
        // call it with dummy data and see what happens
        let mut dummy_data = [0u8; 1];
        let iov = iovec {
            iov_base: dummy_data.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };

        let has_proc_read = unsafe { process_vm_readv(pid, &iov, 1, &iov, 1, 0) } > 0;

        if has_proc_read {
            return Ok(Process { pid, memory: None });
        }

        // process_vm_readv does not work, use /proc/{pid}/mem instead
        let memory = match OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/{pid}/mem"))
        {
            Ok(memory) => memory,
            Err(error) => {
                if error.kind() == ErrorKind::PermissionDenied {
                    return Err(ProcessError::PermissionDenied(pid));
                } else {
                    return Err(ProcessError::FileOpenError(pid));
                }
            }
        };

        Ok(Process {
            pid,
            memory: Some(memory),
        })
    }

    pub fn is_running(&self) -> bool {
        Path::new(&format!("/proc/{}/mem", self.pid)).exists()
    }

    pub fn pid(&self) -> i32 {
        self.pid
    }

    pub fn read<T: AnyBitPattern>(&self, address: usize) -> Result<T, ReadError> {
        let mut buffer = vec![0u8; std::mem::size_of::<T>()];
        if let Some(memory) = &self.memory {
            if let Err(error) = memory.read_at(&mut buffer, address as u64) {
                return Err(if error.kind() == ErrorKind::PermissionDenied {
                    ReadError::PermissionDenied
                } else {
                    ReadError::Unknown
                });
            }
        } else {
            let local_iov = iovec {
                iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
                iov_len: buffer.len(),
            };
            let remote_iov = iovec {
                iov_base: address as *mut libc::c_void,
                iov_len: buffer.len(),
            };

            let bytes_read =
                unsafe { process_vm_readv(self.pid, &local_iov, 1, &remote_iov, 1, 0) };
            if bytes_read < 0 {
                let os_error = Error::last_os_error().raw_os_error();
                return Err(match os_error {
                    Some(EFAULT) => ReadError::OutOfRange,
                    Some(ESRCH) => ReadError::ProcessQuit,
                    Some(EPERM) => ReadError::PermissionDenied,
                    _ => ReadError::Unknown,
                });
            }
        }

        match bytemuck::try_from_bytes::<T>(&buffer).cloned() {
            Ok(value) => Ok(value),
            Err(_) => Err(ReadError::InvalidData(std::any::type_name::<T>())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Process;

    fn pid() -> i32 {
        std::process::id() as i32
    }

    #[test]
    fn create() {
        let process = Process::open_pid(pid());
        assert!(process.is_ok());
    }
}
