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

mod elf;
/// errors for process handling and memory operations
pub mod error;

/// mode used to read and write memory.
#[derive(PartialEq)]
pub enum MemoryMode {
    /// use file i/o on `/proc/{pid}/mem`.
    File,
    /// use `process_vm_readv` and `process_vm_writev` syscalls.
    Syscall,
}

/// represents a process handle for memory operations.
pub struct Process {
    pid: i32,
    memory: File,
    mode: MemoryMode,
}

impl Process {
    fn find_pid<S: AsRef<str>>(name: S) -> Result<i32, ProcessError> {
        for dir in read_dir("/proc").unwrap() {
            let entry = match dir {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            match entry.file_type() {
                Ok(file_type) => {
                    if !file_type.is_dir() {
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

            if exe_name == name.as_ref() {
                let pid = pid
                    .parse::<i32>()
                    .map_err(|error| ProcessError::InvalidPid(error.kind().clone()))?;
                return Ok(pid);
            }
        }
        Err(ProcessError::NotFound)
    }

    fn map_mem_error(error: Error) -> MemoryError {
        if error.kind() == ErrorKind::PermissionDenied {
            MemoryError::PermissionDenied
        } else {
            MemoryError::Unknown
        }
    }

    /// open a process given its executable name.
    ///
    /// this will use the first process with the given name.
    ///
    /// # example
    /// ```rust
    /// let process = Process::open_exe_name("bash").unwrap();
    /// ```
    pub fn open_exe_name<S: AsRef<str>>(name: S) -> Result<Process, ProcessError> {
        let pid = Process::find_pid(name)?;
        Process::open_pid(pid)
    }

    /// open a process from its pid.
    ///
    /// determines availability of `process_vm_*` syscalls and chooses the right mode.
    pub fn open_pid(pid: i32) -> Result<Process, ProcessError> {
        // test whether process_vm_readv is a valid syscall
        // call it with dummy data and see what happens
        let mut dummy_data = [0u8; 1];
        let iov = iovec {
            iov_base: dummy_data.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };

        let has_proc_read = unsafe { process_vm_readv(pid, &iov, 1, &iov, 1, 0) } > 0;

        let memory = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/{pid}/mem"))
            .map_err(|error| {
                if error.kind() == ErrorKind::PermissionDenied {
                    ProcessError::PermissionDenied(pid)
                } else {
                    ProcessError::FileOpenError(pid)
                }
            })?;

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

    /// switch between `Syscall` and `File` mode at runtime.
    pub fn set_mode(&mut self, mode: MemoryMode) {
        self.mode = mode;
    }

    /// check if the process is still running and valid
    pub fn is_running(&self) -> bool {
        Path::new(&format!("/proc/{}/mem", self.pid)).exists()
    }

    /// get the pid of the target process.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// read a value T from the specified address.
    ///
    /// the type must implement [`bytemuck::AnyBitPattern`].
    /// in Syscall mode uses `process_vm_readv`, in File mode uses FileExt::read_at.
    pub fn read<T: AnyBitPattern>(&self, address: usize) -> Result<T, MemoryError> {
        let mut buffer = vec![0u8; std::mem::size_of::<T>()];
        if self.mode == MemoryMode::File {
            self.memory
                .read_at(&mut buffer, address as u64)
                .map_err(Process::map_mem_error)?;
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
            } else if (bytes_read as usize) < buffer.len() {
                return Err(MemoryError::PartialTransfer(
                    bytes_read as usize,
                    buffer.len(),
                ));
            }
        }

        match bytemuck::try_from_bytes::<T>(&buffer).cloned() {
            Ok(value) => Ok(value),
            Err(_) => Err(MemoryError::InvalidData(std::any::type_name::<T>())),
        }
    }

    /// write a value T to the specified address.
    ///
    /// the type must implement [`bytemuck::NoUninit`].
    /// in Syscall mode uses `process_vm_writev`, in File mode uses FileExt::write_at.
    pub fn write<T: NoUninit>(&self, address: usize, value: &T) -> Result<(), MemoryError> {
        let mut buffer = bytemuck::bytes_of(value).to_vec();
        if self.mode == MemoryMode::File {
            self.memory
                .write_at(&buffer, address as u64)
                .map_err(Process::map_mem_error)?;
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
            } else if (bytes_written as usize) < buffer.len() {
                return Err(MemoryError::PartialTransfer(
                    bytes_written as usize,
                    buffer.len(),
                ));
            }
        }

        Ok(())
    }

    /// reads `count` bytes starting at `address`, using File mode.
    ///
    /// process_vm_readv does not work for very large reads,
    /// which is why File mode is always used.
    /// it will not switch the mode for other reads and writes.
    pub fn read_bytes(&self, address: usize, count: usize) -> Result<Vec<u8>, MemoryError> {
        let mut buffer = vec![0u8; count];
        self.memory
            .read_at(&mut buffer, address as u64)
            .map_err(Process::map_mem_error)?;
        Ok(buffer)
    }

    /// writes `count` bytes starting at `address`, using File mode.
    ///
    /// process_vm_writev does not work for very large writes,
    /// which is why File mode is always used.
    /// it will not switch the mode for other reads and writes.
    pub fn write_bytes(&self, address: usize, value: &[u8]) -> Result<(), MemoryError> {
        self.memory
            .write_at(value, address as u64)
            .map_err(Process::map_mem_error)?;
        Ok(())
    }

    /// reads a c-style null-terminated string starting at `address`
    /// until a `0` byte.
    pub fn read_terminated_string(&self, address: usize) -> Result<String, MemoryError> {
        const MAX_BYTES: usize = 1024;
        const SIZE: usize = 32;
        let mut buffer = Vec::with_capacity(SIZE);
        let mut current_address = address;
        let mut bytes_read = 0;
        loop {
            let chunk = self.read_bytes(current_address, SIZE)?;
            bytes_read += SIZE;

            if let Some(null_pos) = chunk.iter().position(|&b| b == 0) {
                buffer.extend_from_slice(&chunk[..null_pos]);
                return Ok(String::from_utf8_lossy(&buffer).to_string());
            }

            buffer.extend_from_slice(&chunk);
            current_address += SIZE;

            if bytes_read >= MAX_BYTES {
                return Err(MemoryError::StringTooLong);
            }
        }
    }

    /// reads a utf-8 encoded string starting at `address` with a given length.
    pub fn read_string(&self, address: usize, length: usize) -> Result<String, MemoryError> {
        let bytes = self.read_bytes(address, length)?;
        String::from_utf8(bytes)
            .map_err(|_| MemoryError::InvalidData(std::any::type_name::<String>()))
    }

    /// writes any string-like starting at `address`
    pub fn write_string<S: AsRef<str>>(&self, address: usize, value: S) -> Result<(), MemoryError> {
        self.write_bytes(address, value.as_ref().as_bytes())
    }

    /// parses `/proc/{pid}/maps` to locate the base address of a loaded
    /// library with name matching `library`.
    pub fn find_library<S: AsRef<str>>(&self, library: S) -> Result<usize, MemoryError> {
        let maps =
            File::open(format!("/proc/{}/maps", self.pid)).map_err(Process::map_mem_error)?;
        for line in BufReader::new(maps).lines() {
            let Ok(line) = line else {
                continue;
            };
            let Some((line, file_name)) = line.rsplit_once('/') else {
                continue;
            };
            if !file_name.contains(library.as_ref()) {
                continue;
            }
            let Some((address, _)) = line.split_once('-') else {
                return Err(MemoryError::Unknown);
            };
            let address = usize::from_str_radix(address, 16)
                .map_err(|_| MemoryError::InvalidData(std::any::type_name::<usize>()))?;
            return Ok(address);
        }
        Err(MemoryError::NotFound)
    }

    /// returns the size of a library at `address`, in bytes.
    pub fn library_size(&self, address: usize) -> Result<usize, MemoryError> {
        // check if elf header is present
        let header = self.read::<u32>(address)?;
        if header != 0x464C457F && header != 0x7F454C46 {
            return Err(MemoryError::OutOfRange);
        }
        let section_header_offset = self.read::<usize>(address + elf::SECTION_HEADER_OFFSET)?;
        let section_header_entry_size =
            self.read::<u16>(address + elf::SECTION_HEADER_ENTRY_SIZE)? as usize;
        let section_header_num_entries =
            self.read::<u16>(address + elf::SECTION_HEADER_NUM_ENTRIES)? as usize;

        Ok(section_header_offset + section_header_entry_size * section_header_num_entries)
    }

    /// dump a library at base address `address`.
    /// this will return a complete copy of the library, as it is loaded into memory.
    pub fn dump_library(&self, address: usize) -> Result<Vec<u8>, MemoryError> {
        // check if elf header is present
        let header = self.read::<u32>(address)?;
        if header != 0x464C457F && header != 0x7F454C46 {
            return Err(MemoryError::OutOfRange);
        }
        let lib_size = self.library_size(address)?;
        self.read_bytes(address, lib_size)
    }

    /// scan a pattern in library at `address`, using `pattern`.
    ///
    /// the pattern accepted is a normal ida pattern.
    ///
    /// # example
    ///
    /// ```rust
    /// let process = Process::open_exe_name("bash").unwrap();
    /// process.scan_pattern("12 34 ? ? 56 78", 0x12345678);
    /// ```
    ///
    /// this scans the ida pattern `12 34 ? ? 56 78`.
    pub fn scan_pattern<S: AsRef<str>>(
        &self,
        pattern: S,
        address: usize,
    ) -> Result<usize, MemoryError> {
        let pattern_string = pattern.as_ref();
        let mut pattern = Vec::with_capacity(pattern_string.len());
        let mut mask = Vec::with_capacity(pattern_string.len());

        for c in pattern_string.split(' ') {
            match u8::from_str_radix(c, 16) {
                Ok(c) => {
                    pattern.push(c);
                    mask.push(1);
                }
                Err(_) => {
                    pattern.push(0);
                    mask.push(0);
                }
            }
        }

        let module = self.dump_library(address)?;
        if module.len() < 500 {
            return Err(MemoryError::InvalidLibrary);
        }

        let pattern_length = pattern.len();
        let stop_index = module.len() - pattern_length;
        'outer: for i in 0..stop_index {
            for j in 0..pattern_length {
                if mask[j] != 0 && module[i + j] != pattern[j] {
                    continue 'outer;
                }
            }
            return Ok(address + i);
        }
        Err(MemoryError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use crate::error::MemoryError;

    use super::Process;

    /// get own process pid.
    fn pid() -> i32 {
        std::process::id() as i32
    }

    #[test]
    fn create() {
        assert!(Process::open_pid(pid()).is_ok());
    }

    #[test]
    fn read() -> Result<(), MemoryError> {
        let process = Process::open_pid(pid()).unwrap();
        let buffer = [0x55u8];
        let value = process.read::<u8>(buffer.as_ptr() as usize)?;
        assert!(value == buffer[0]);
        Ok(())
    }

    #[test]
    fn write() -> Result<(), MemoryError> {
        let process = Process::open_pid(pid()).unwrap();
        let buffer = [0x55u8];
        const VALUE: u8 = 0x66;
        process.write::<u8>(buffer.as_ptr() as usize, &VALUE)?;
        assert!(buffer[0] == VALUE);
        Ok(())
    }

    #[test]
    fn read_bytes() -> Result<(), MemoryError> {
        let process = Process::open_pid(pid()).unwrap();
        let buffer: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        let value = process.read_bytes(buffer.as_ptr() as usize, 4)?;
        assert!(value == buffer);
        Ok(())
    }

    #[test]
    fn write_bytes() -> Result<(), MemoryError> {
        let process = Process::open_pid(pid()).unwrap();
        let buffer: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        const VALUE: [u8; 4] = [0x55, 0x66, 0x77, 0x88];
        process.write_bytes(buffer.as_ptr() as usize, &VALUE)?;
        assert!(buffer == VALUE);
        Ok(())
    }

    #[test]
    fn read_terminated_string() -> Result<(), MemoryError> {
        let process = Process::open_pid(pid()).unwrap();
        const STRING: &str = "Hello World";
        let buffer = std::ffi::CString::new(STRING).unwrap();
        let value = process.read_terminated_string(buffer.as_ptr() as usize)?;
        assert!(value == *STRING);
        Ok(())
    }

    #[test]
    fn read_string() -> Result<(), MemoryError> {
        let process = Process::open_pid(pid()).unwrap();
        const STRING: &str = "Hello World";
        let value = process.read_string(STRING.as_ptr() as usize, STRING.len())?;
        assert!(value == STRING);
        Ok(())
    }

    #[test]
    fn scan_pattern() -> Result<(), MemoryError> {
        let process = Process::open_pid(pid()).unwrap();
        const STRING: &str = "Hello World";

        // find loaded process elf
        let exe_path = std::env::current_exe().unwrap();
        let exe_name = exe_path.file_name().unwrap().to_str().unwrap();
        let lib = process.find_library(exe_name)?;

        // convert hello world string to ida pattern
        let pattern = STRING
            .as_bytes()
            .iter()
            .map(|c| format!("{:02x}", c))
            .collect::<Vec<String>>()
            .join(" ");

        let value = process.scan_pattern(pattern, lib)?;
        assert!(value == STRING.as_ptr() as usize);
        Ok(())
    }
}
