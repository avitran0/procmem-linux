# procmem-linux

a library to read and write process memory on linux

## example

```rust
use procmem_linux::{Process};

// open a process by its pid
let process = Process::open_pid(1234).unwrap();
// open a process by its executable name (first that is found with matching name)
let process = Process::open_exe_name("executable");

// read a value from a given address
let read_value: i32 = process.read(0x1234);
```

by default, it tries to read and write memory using the `process_vm_readv/writev` syscalls,
but it can be forced to read from `/proc/{pid}/mem` by changing the process mode:

```rust
use procmem_linux::{Process, MemoryMode};

let mut process = Process::open_pid(1234).unwrap();
process.set_mode(MemoryMode::File);
```
