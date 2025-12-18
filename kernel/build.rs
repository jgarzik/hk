// Build script for hk-kernel

use std::path::Path;
use std::process::Command;

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = std::env::var("OUT_DIR").unwrap();

    // x86_64 bare-metal target
    if target == "x86_64-unknown-none" {
        let arch_dir = Path::new(&manifest_dir).join("arch/x86_64");

        // Assemble boot.S
        let boot_s = arch_dir.join("boot.S");
        let boot_o = Path::new(&out_dir).join("boot.o");

        let status = Command::new("as")
            .args(["--64", "-o"])
            .arg(&boot_o)
            .arg(&boot_s)
            .status()
            .expect("Failed to run assembler");

        if !status.success() {
            panic!("Failed to assemble boot.S");
        }

        // Assemble trampoline.S (AP startup code)
        let trampoline_s = arch_dir.join("trampoline.S");
        let trampoline_o = Path::new(&out_dir).join("trampoline.o");

        let status = Command::new("as")
            .args(["--64", "-o"])
            .arg(&trampoline_o)
            .arg(&trampoline_s)
            .status()
            .expect("Failed to run assembler for trampoline.S");

        if !status.success() {
            panic!("Failed to assemble trampoline.S");
        }

        // Assemble switch_to.S (context switch)
        let switch_to_s = arch_dir.join("switch_to.S");
        let switch_to_o = Path::new(&out_dir).join("switch_to.o");

        let status = Command::new("as")
            .args(["--64", "-o"])
            .arg(&switch_to_o)
            .arg(&switch_to_s)
            .status()
            .expect("Failed to run assembler for switch_to.S");

        if !status.success() {
            panic!("Failed to assemble switch_to.S");
        }

        // Link the object files
        println!("cargo:rustc-link-arg={}", boot_o.display());
        println!("cargo:rustc-link-arg={}", trampoline_o.display());
        println!("cargo:rustc-link-arg={}", switch_to_o.display());
        println!(
            "cargo:rustc-link-arg=-T{}",
            arch_dir.join("kernel.ld").display()
        );

        // Rerun if sources change
        println!("cargo:rerun-if-changed=arch/x86_64/kernel.ld");
        println!("cargo:rerun-if-changed=arch/x86_64/boot.S");
        println!("cargo:rerun-if-changed=arch/x86_64/trampoline.S");
        println!("cargo:rerun-if-changed=initramfs-x86_64.cpio");
    }

    // aarch64 bare-metal target
    if target == "aarch64-unknown-none" {
        let arch_dir = Path::new(&manifest_dir).join("arch/aarch64");

        // Assemble boot.S with aarch64 cross-assembler
        let boot_s = arch_dir.join("boot.S");
        let boot_o = Path::new(&out_dir).join("boot.o");

        let status = Command::new("aarch64-linux-gnu-as")
            .args(["-o"])
            .arg(&boot_o)
            .arg(&boot_s)
            .status()
            .expect("Failed to run aarch64 assembler - install aarch64-linux-gnu-binutils");

        if !status.success() {
            panic!("Failed to assemble boot.S for aarch64");
        }

        // Assemble vectors.S (exception vector table)
        let vectors_s = arch_dir.join("vectors.S");
        let vectors_o = Path::new(&out_dir).join("vectors.o");

        let status = Command::new("aarch64-linux-gnu-as")
            .args(["-o"])
            .arg(&vectors_o)
            .arg(&vectors_s)
            .status()
            .expect("Failed to run aarch64 assembler for vectors.S");

        if !status.success() {
            panic!("Failed to assemble vectors.S for aarch64");
        }

        // Assemble switch_to.S (context switch)
        let switch_to_s = arch_dir.join("switch_to.S");
        let switch_to_o = Path::new(&out_dir).join("switch_to.o");

        let status = Command::new("aarch64-linux-gnu-as")
            .args(["-o"])
            .arg(&switch_to_o)
            .arg(&switch_to_s)
            .status()
            .expect("Failed to run aarch64 assembler for switch_to.S");

        if !status.success() {
            panic!("Failed to assemble switch_to.S for aarch64");
        }

        // Link the object files (linker script is already in .cargo/config.toml)
        println!("cargo:rustc-link-arg={}", boot_o.display());
        println!("cargo:rustc-link-arg={}", vectors_o.display());
        println!("cargo:rustc-link-arg={}", switch_to_o.display());

        // Rerun if sources change
        println!("cargo:rerun-if-changed=arch/aarch64/kernel.ld");
        println!("cargo:rerun-if-changed=arch/aarch64/boot.S");
        println!("cargo:rerun-if-changed=arch/aarch64/vectors.S");
        println!("cargo:rerun-if-changed=arch/aarch64/switch_to.S");
        println!("cargo:rerun-if-changed=../user/initramfs-aarch64.cpio");
    }
}
