//! Boot test harness for hk kernel
//!
//! Builds the kernel, runs it in QEMU, and watches for BOOT_COMPLETE marker.
//! Exits with code 0 on success, 1 on timeout, or QEMU's exit code on crash.
//!
//! Usage: cargo run -p hk-tools --bin boot-test [-- --timeout SECONDS]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT_SECS: u64 = 10;
const SUCCESS_MARKER: &str = "BOOT_COMPLETE";

fn main() {
    let timeout_secs = parse_timeout();
    let timeout = Duration::from_secs(timeout_secs);

    // Step 1: Build kernel and ISO
    println!("[boot-test] Building kernel and ISO...");
    let status = Command::new("make")
        .args(["iso"])
        .status()
        .expect("Failed to run make");

    if !status.success() {
        eprintln!("[boot-test] Build failed");
        std::process::exit(2);
    }

    // Step 2: Start QEMU with ISO (BIOS boot)
    println!("[boot-test] Starting QEMU (timeout: {}s)...", timeout_secs);
    let start = Instant::now();

    let mut qemu = Command::new("qemu-system-x86_64")
        .args([
            "-M",
            "pc",
            "-cpu",
            "qemu64",
            "-m",
            "512M",
            "-cdrom",
            "target/hk-x86_64.iso",
            "-serial",
            "stdio",
            "-display",
            "none",
            "-no-reboot",
            "-no-shutdown",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start QEMU");

    // Step 3: Watch output for marker or timeout
    let result = watch_output(&mut qemu, timeout);

    // Step 4: Cleanup and report
    let _ = qemu.kill();
    let elapsed = start.elapsed();

    match result {
        WatchResult::Success => {
            println!(
                "[boot-test] Success: kernel booted in {:.1}s",
                elapsed.as_secs_f64()
            );
            std::process::exit(0);
        }
        WatchResult::Timeout => {
            eprintln!(
                "[boot-test] Timeout: no BOOT_COMPLETE after {:.1}s",
                elapsed.as_secs_f64()
            );
            std::process::exit(1);
        }
        WatchResult::QemuExited(code) => {
            eprintln!(
                "[boot-test] QEMU exited with code {} after {:.1}s",
                code,
                elapsed.as_secs_f64()
            );
            std::process::exit(code);
        }
    }
}

fn parse_timeout() -> u64 {
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len() {
        if args[i] == "--timeout"
            && let Some(val) = args.get(i + 1)
        {
            return val.parse().unwrap_or(DEFAULT_TIMEOUT_SECS);
        }
    }
    DEFAULT_TIMEOUT_SECS
}

enum WatchResult {
    Success,
    Timeout,
    QemuExited(i32),
}

fn watch_output(qemu: &mut Child, timeout: Duration) -> WatchResult {
    let stdout = qemu.stdout.take().expect("No stdout");
    let (tx, rx) = mpsc::channel();

    // Spawn thread to read stdout line by line
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(text) => {
                    println!("{}", text);
                    if text.contains(SUCCESS_MARKER) {
                        let _ = tx.send(WatchResult::Success);
                        return;
                    }
                }
                Err(_) => {
                    // QEMU exited (pipe closed)
                    let _ = tx.send(WatchResult::QemuExited(1));
                    return;
                }
            }
        }
        // EOF means QEMU exited
        let _ = tx.send(WatchResult::QemuExited(1));
    });

    // Wait for result or timeout
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(_) => WatchResult::Timeout,
    }
}
