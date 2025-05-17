# procmem-linux

[![crates.io](https://img.shields.io/crates/v/procmem-linux
)](https://crates.io/crates/procmem-linux)
[![docs.rs](https://img.shields.io/docsrs/procmem-linux)](https://docs.rs/procmem-linux)

a library to read and write process memory on linux

## features

- locate processes by executable name or pid
- read/write any type that implements [`bytemuck::AnyBitPattern`](https://docs.rs/bytemuck/latest/bytemuck/trait.AnyBitPattern.html) (reads) and [`bytemuck::NoUninit`](https://docs.rs/bytemuck/latest/bytemuck/trait.NoUninit.html) (writes)
- read c-style null terminated and fixed-length strings
- read/write arbitrary bite slices
- find base addresses of loaded libraries

## quick start

```rust
use process_memory::{Process, MemoryMode, error::MemoryError};

fn main() -> Result<(), MemoryError> {
    // open a process by name or pid
    let mut proc = Process::open_exe_name("target_executable")?;

    // optionally switch to file-based mode
    proc.set_mode(MemoryMode::File);

    // read a value of type T at a given address
    let value: u32 = proc.read(0x7ffd_1234_5678)?;
    println!("value at address: {}", value);

    // write a new value
    proc.write(0x7ffd_1234_5678, &42u32)?;

    // read a null-terminated string
    let message = proc.read_terminated_string(0x7ffd_1234_9000)?;
    println!("message: {}", message);

    // write a string
    proc.write_string(0x7ffd_1234_5678, "Hello World")?;

    // read a vector of type T of length 4 at a given address
    let value_vec: Vec<u8> = proc.read(0x7ffd_1234_5678, 4)?;
    println!("values at address: {:?}", value_vec);

    // scan an ida pattern ("Hello World", with two wildcards)
    let pattern = proc.scan_pattern("48 65 ? ? 6f 20 57 6f 72 6c 64", 0x7ffd_1234_5678)?;
    println!("pattern address: {}", pattern);

    Ok(())
}
```

## memory mode

the crate works in two different modes: `Syscall` and `File` mode.

in **Syscall mode**, it tries to use `process_vm_readv` and `process_vm_writev` to avoid copies and avoid detection.
this requires `kernel >= 3.2` and `glibc >= 2.15`.

in **File mode**, it opens `/proc/{pid}/mem` and uses normal read/write syscalls.
this is slower, but might be necessary as a fallback, or when write permissions are restricted.

File mode is about 12.5% slower than Syscall mode, based on rudimentary benchmarks.

the default mode is to try and use syscall mode, but this can be overridden if wanted:

```rust
use procmem_linux::{Process, MemoryMode};

let mut process = Process::open_pid(1234).unwrap();
process.set_mode(MemoryMode::File);
```
