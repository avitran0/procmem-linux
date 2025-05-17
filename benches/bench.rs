use criterion::{Criterion, criterion_group, criterion_main};
use std::ffi::CString;
use std::{hint::black_box, path::PathBuf};

use procmem_linux::{MemoryMode, Process};

/// Helper to get current process ID
fn pid() -> i32 {
    std::process::id() as i32
}

const fn u64() -> [u8; 8] {
    0x1234567890abcdefu64.to_ne_bytes()
}

const fn u64_inv() -> [u8; 8] {
    0xfedcba0987654321u64.to_ne_bytes()
}

pub fn bench_open_pid(c: &mut Criterion) {
    c.bench_function("open_pid", |b| {
        b.iter(|| {
            let _ = Process::open_pid(black_box(pid())).unwrap();
        });
    });
}

pub fn bench_read_u64(c: &mut Criterion) {
    let process = Process::open_pid(pid()).unwrap();
    let buffer = u64();
    let addr = buffer.as_ptr() as usize;

    c.bench_function("read_u64", |b| {
        b.iter(|| {
            let _ = process.read::<u64>(black_box(addr)).unwrap();
        });
    });
}

pub fn bench_read_vec(c: &mut Criterion) {
    let process = Process::open_pid(pid()).unwrap();
    let buffer = [0x11u8, 0x22, 0x33, 0x44];
    let addr = buffer.as_ptr() as usize;
    c.bench_function("read_vec", |b| {
        b.iter(|| {
            let _ = process.read_vec::<u8>(addr, buffer.len()).unwrap();
        });
    });
}

pub fn bench_write_u64(c: &mut Criterion) {
    let process = Process::open_pid(pid()).unwrap();
    let buffer = u64();
    const VALUE: u64 = 0xfedcba0987654321;
    let addr = buffer.as_ptr() as usize;

    c.bench_function("write_u64", |b| {
        b.iter(|| {
            process
                .write::<u64>(black_box(addr), black_box(&VALUE))
                .unwrap();
        });
    });
}

pub fn bench_write_vec(c: &mut Criterion) {
    let process = Process::open_pid(pid()).unwrap();
    let mut buffer = [0x11u8, 0x22, 0x33, 0x44];
    let addr = buffer.as_mut_ptr() as usize;
    let to_write = [0x44u8, 0x33, 0x22, 0x11];

    c.bench_function("write_vec", |b| {
        b.iter(|| {
            process.write_vec(addr, &to_write).unwrap();
        })
    });
}

pub fn bench_read_u64_syscall(c: &mut Criterion) {
    let mut process = Process::open_pid(pid()).unwrap();
    process.set_mode(MemoryMode::Syscall);
    let buffer = u64();
    let addr = buffer.as_ptr() as usize;

    c.bench_function("read_u64_syscall", |b| {
        b.iter(|| {
            let _ = process.read::<u64>(black_box(addr)).unwrap();
        });
    });
}

pub fn bench_read_u64_file(c: &mut Criterion) {
    let mut process = Process::open_pid(pid()).unwrap();
    process.set_mode(MemoryMode::File);
    let buffer = u64();
    let addr = buffer.as_ptr() as usize;

    c.bench_function("read_u64_file", |b| {
        b.iter(|| {
            let _ = process.read::<u64>(black_box(addr)).unwrap();
        });
    });
}

pub fn bench_read_bytes(c: &mut Criterion) {
    let process = Process::open_pid(pid()).unwrap();
    let buffer = u64();
    let addr = buffer.as_ptr() as usize;

    c.bench_function("read_bytes", |b| {
        b.iter(|| {
            let _ = process.read_bytes(black_box(addr), black_box(8)).unwrap();
        });
    });
}

pub fn bench_write_bytes(c: &mut Criterion) {
    let process = Process::open_pid(pid()).unwrap();
    let buffer = u64();
    const VALUE: [u8; 8] = u64_inv();
    let addr = buffer.as_ptr() as usize;

    c.bench_function("write_bytes", |b| {
        b.iter(|| {
            process
                .write_bytes(black_box(addr), black_box(&VALUE))
                .unwrap();
        });
    });
}

pub fn bench_read_terminated_string(c: &mut Criterion) {
    let process = Process::open_pid(pid()).unwrap();
    const STRING: &str = "Hello World";
    let buffer = CString::new(STRING).unwrap();
    let addr = buffer.as_ptr() as usize;

    c.bench_function("read_terminated_string", |b| {
        b.iter(|| {
            let _ = process.read_terminated_string(black_box(addr)).unwrap();
        });
    });
}

pub fn bench_read_string(c: &mut Criterion) {
    let process = Process::open_pid(pid()).unwrap();
    const STRING: &str = "Hello World";
    let addr = STRING.as_ptr() as usize;
    const LEN: usize = STRING.len();

    c.bench_function("read_string", |b| {
        b.iter(|| {
            let _ = process
                .read_string(black_box(addr), black_box(LEN))
                .unwrap();
        });
    });
}

pub fn bench_scan_pattern(c: &mut Criterion) {
    let process = Process::open_pid(pid()).unwrap();
    const STRING: &str = "Hello World";

    // prepare library name
    let exe_path: PathBuf = std::env::current_exe().unwrap();
    let exe_name = exe_path.file_name().unwrap().to_str().unwrap();
    let lib = process.find_library(exe_name).unwrap();

    // prepare pattern
    let pattern = STRING
        .as_bytes()
        .iter()
        .map(|c| format!("{:02x}", c))
        .collect::<Vec<String>>()
        .join(" ");

    c.bench_function("scan_pattern", |b| {
        b.iter(|| {
            let _ = process
                .scan_pattern(black_box(pattern.clone()), black_box(lib))
                .unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_open_pid,
    bench_read_u64,
    bench_read_vec,
    bench_write_u64,
    bench_write_vec,
    bench_read_u64_syscall,
    bench_read_u64_file,
    bench_read_bytes,
    bench_write_bytes,
    bench_read_terminated_string,
    bench_read_string,
    bench_scan_pattern
);
criterion_main!(benches);
