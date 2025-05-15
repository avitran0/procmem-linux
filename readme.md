# procmem-linux

a library to read and write process memory on linux

## example

```rust
let process = Process::open_pid(1234).unwrap();
let read_value: i32 = process.read(0x1234);
```

by default, it tries to read and write memory using the `process_vm_readv/writev` syscalls,
but it can be forced to read from `/proc/{pid}/mem` by changing the process mode:

```rust
let mut process = Process::open_pid(1234).unwrap();
process.set_mode(MemoryMode::File);
```
