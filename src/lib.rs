#![doc = include_str!("../readme.md")]

use std::{
    fs::{File, OpenOptions, read_dir, read_link},
    io::{BufRead, BufReader, Error, ErrorKind},
    os::unix::fs::FileExt,
    path::Path,
};

use bytemuck::{AnyBitPattern, NoUninit};
use error::{MemoryError, ProcessError};
use libc::{EFAULT, EPERM, ESRCH, iovec, process_vm_readv, process_vm_writev};

pub mod error;

#[derive(PartialEq)]
pub enum MemoryMode {
    File,
    Syscall,
}

/// representation of a process to read/write memory to.
pub struct Process {
    pid: i32,
    memory: File,
    mode: MemoryMode,
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

    /// open a process given its executable name.
    pub fn open_exe_name(name: &str) -> Result<Process, ProcessError> {
        let pid = Process::find_pid(name)?;
        Process::open_pid(pid)
    }

    /// open a process from its pid.
    pub fn open_pid(pid: i32) -> Result<Process, ProcessError> {
        // test whether process_vm_readv is a valid syscall
        // call it with dummy data and see what happens
        let mut dummy_data = [0u8; 1];
        let iov = iovec {
            iov_base: dummy_data.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };

        let has_proc_read = unsafe { process_vm_readv(pid, &iov, 1, &iov, 1, 0) } > 0;

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
            memory,
            mode: if has_proc_read {
                MemoryMode::Syscall
            } else {
                MemoryMode::File
            },
        })
    }

    pub fn set_mode(&mut self, mode: MemoryMode) {
        self.mode = mode;
    }

    /// whether the opened process is still running and valid
    pub fn is_running(&self) -> bool {
        Path::new(&format!("/proc/{}/mem", self.pid)).exists()
    }

    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// read a value from an address
    pub fn read<T: AnyBitPattern>(&self, address: usize) -> Result<T, MemoryError> {
        let mut buffer = vec![0u8; std::mem::size_of::<T>()];
        if self.mode == MemoryMode::File {
            if let Err(error) = &self.memory.read_at(&mut buffer, address as u64) {
                return Err(if error.kind() == ErrorKind::PermissionDenied {
                    MemoryError::PermissionDenied
                } else {
                    MemoryError::Unknown
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
                    Some(EFAULT) => MemoryError::OutOfRange,
                    Some(ESRCH) => MemoryError::ProcessQuit,
                    Some(EPERM) => MemoryError::PermissionDenied,
                    _ => MemoryError::Unknown,
                });
            }
        }

        match bytemuck::try_from_bytes::<T>(&buffer).cloned() {
            Ok(value) => Ok(value),
            Err(_) => Err(MemoryError::InvalidData(std::any::type_name::<T>())),
        }
    }

    /// write a value to an address
    pub fn write<T: NoUninit>(&self, address: usize, value: &T) -> Result<(), MemoryError> {
        let mut buffer = bytemuck::bytes_of(value).to_vec();
        if self.mode == MemoryMode::File {
            if let Err(error) = &self.memory.write_at(&buffer, address as u64) {
                return Err(if error.kind() == ErrorKind::PermissionDenied {
                    MemoryError::PermissionDenied
                } else {
                    MemoryError::Unknown
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

            let bytes_written =
                unsafe { process_vm_writev(self.pid, &local_iov, 1, &remote_iov, 1, 0) };
            if bytes_written < 0 {
                let os_error = Error::last_os_error().raw_os_error();
                return Err(match os_error {
                    Some(EFAULT) => MemoryError::OutOfRange,
                    Some(ESRCH) => MemoryError::ProcessQuit,
                    Some(EPERM) => MemoryError::PermissionDenied,
                    _ => MemoryError::Unknown,
                });
            }
        }

        Ok(())
    }

    pub fn read_bytes(&self, address: usize, count: usize) -> Result<Vec<u8>, MemoryError> {
        let mut buffer = vec![0u8; count];
        if let Err(error) = self.memory.read_at(&mut buffer, address as u64) {
            return Err(if error.kind() == ErrorKind::PermissionDenied {
                MemoryError::PermissionDenied
            } else {
                MemoryError::Unknown
            });
        }
        Ok(buffer)
    }

    pub fn write_bytes(&self, address: usize, value: &[u8]) -> Result<(), MemoryError> {
        if let Err(error) = self.memory.write_at(value, address as u64) {
            return Err(if error.kind() == ErrorKind::PermissionDenied {
                MemoryError::PermissionDenied
            } else {
                MemoryError::Unknown
            });
        }
        Ok(())
    }

    /// reads a null-terminated string.
    pub fn read_terminated_string(&self, address: usize) -> Result<String, MemoryError> {
        let mut value = String::with_capacity(8);
        let mut i = address;
        loop {
            let c = self.read::<u8>(i)?;
            if c == 0 {
                break;
            }
            value.push(c as char);
            i += 1;
        }
        Ok(value)
    }

    /// reads a string with a given length.
    pub fn read_string(&self, address: usize, length: usize) -> Result<String, MemoryError> {
        let bytes = self.read_bytes(address, length)?;
        match String::from_utf8(bytes) {
            Ok(str) => Ok(str),
            Err(_) => Err(MemoryError::InvalidData(std::any::type_name::<String>())),
        }
    }

    /// tries to find the address of a library loaded into the process.
    pub fn find_library(&self, library: &str) -> Option<usize> {
        let maps = File::open(format!("/proc/{}/maps", self.pid)).unwrap();
        for line in BufReader::new(maps).lines() {
            if line.is_err() {
                continue;
            }
            let line = line.unwrap();
            if !line.contains(library) {
                continue;
            }
            let (address, _) = line.split_once('-').unwrap();
            let address = usize::from_str_radix(address, 16).unwrap();
            return Some(address);
        }
        None
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

    #[test]
    fn read() {
        let process = Process::open_pid(pid()).unwrap();
        let buffer = [0x55u8];
        let value = process.read::<u8>(buffer.as_ptr() as usize);
        assert!(value.is_ok());
        assert!(value.unwrap() == 0x55u8);
    }

    #[test]
    fn write() {
        let process = Process::open_pid(pid()).unwrap();
        let buffer = [0x55u8];
        let result = process.write::<u8>(buffer.as_ptr() as usize, &0x66);
        assert!(result.is_ok());
        assert!(buffer[0] == 0x66u8);
    }

    #[test]
    fn read_bytes() {
        let process = Process::open_pid(pid()).unwrap();
        let buffer: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        let value = process.read_bytes(buffer.as_ptr() as usize, 4);
        assert!(value.is_ok());
        assert!(value.unwrap() == buffer);
    }

    #[test]
    fn write_bytes() {
        let process = Process::open_pid(pid()).unwrap();
        let buffer: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        let result = process.write_bytes(buffer.as_ptr() as usize, &[0x55, 0x66, 0x77, 0x88]);
        assert!(result.is_ok());
        assert!(buffer == [0x55, 0x66, 0x77, 0x88]);
    }

    #[test]
    fn read_terminated_string() {
        let process = Process::open_pid(pid()).unwrap();
        const STRING: &str = "Hello World";
        let buffer = std::ffi::CString::new(STRING).unwrap();
        let value = process.read_terminated_string(buffer.as_ptr() as usize);
        assert!(value.is_ok());
        assert!(value.unwrap() == *STRING);
    }

    #[test]
    fn read_string() {
        let process = Process::open_pid(pid()).unwrap();
        let buffer = "Hello World";
        let value = process.read_string(buffer.as_ptr() as usize, buffer.len());
        assert!(value.is_ok());
        assert!(value.unwrap() == buffer);
    }
}
