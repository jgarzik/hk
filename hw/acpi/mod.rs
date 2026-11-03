//! ACPI, arch-neutral parts (Linux drivers/acpi, ACPICA): sleep state
//! values found in AML, and the fixed-hardware sleep sequence
//!
//! Locking: none (boot-time parsing; the sleep path runs once, last).

pub mod aml;
pub mod hw;
