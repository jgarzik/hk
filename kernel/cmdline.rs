//! Kernel command line parsing
//!
//! Parses kernel command line options and applies them to kernel subsystems.
//!
//! ## Supported Options
//!
//! - `usb_trace` - Enable USB protocol tracing for debugging
//! - `console=<device>[,<options>]` - Set kernel console device
//!   - Examples: `console=ttyS0`, `console=ttyS0,115200`
//!   - Multiple console= options can be specified; all receive output
//!   - The last one specified is the primary console

use crate::usb;
use spin::Mutex;

/// Maximum number of console specifications from command line
const MAX_CONSOLE_SPECS: usize = 4;

/// Console specification from command line
#[derive(Clone, Copy)]
pub struct ConsoleSpec {
    /// Device name (e.g., "ttyS0", "ttyUSB0")
    pub device: [u8; 16],
    /// Device name length
    pub device_len: usize,
    /// Baud rate (0 = default)
    pub baud_rate: u32,
}

impl ConsoleSpec {
    /// Create a new empty console spec
    const fn empty() -> Self {
        Self {
            device: [0; 16],
            device_len: 0,
            baud_rate: 0,
        }
    }

    /// Get device name as str
    pub fn device_name(&self) -> &str {
        core::str::from_utf8(&self.device[..self.device_len]).unwrap_or("")
    }

    /// Check if this spec matches a device name
    pub fn matches(&self, name: &str) -> bool {
        self.device_name() == name
    }
}

/// Global console specifications from command line
struct CmdlineConsole {
    /// Console specifications
    specs: [ConsoleSpec; MAX_CONSOLE_SPECS],
    /// Number of valid specs
    count: usize,
}

impl CmdlineConsole {
    const fn new() -> Self {
        Self {
            specs: [ConsoleSpec::empty(); MAX_CONSOLE_SPECS],
            count: 0,
        }
    }
}

static CMDLINE_CONSOLE: Mutex<CmdlineConsole> = Mutex::new(CmdlineConsole::new());

/// Parse kernel command line and apply options
///
/// Supported options:
/// - `usb_trace`: Enable USB protocol tracing for debugging
/// - `console=<device>[,<baud>]`: Set kernel console device
pub fn parse_cmdline(cmdline: &str) {
    for option in cmdline.split_whitespace() {
        if option == "usb_trace" {
            usb::enable_usb_trace();
        } else if let Some(console_arg) = option.strip_prefix("console=") {
            parse_console_option(console_arg);
        }
        // Unknown options are ignored
    }
}

/// Parse a console= option
///
/// Format: `console=<device>[,<baud>]`
/// Examples: `console=ttyS0`, `console=ttyS0,115200`
fn parse_console_option(arg: &str) {
    let mut console = CMDLINE_CONSOLE.lock();

    if console.count >= MAX_CONSOLE_SPECS {
        return; // Too many console specs, ignore
    }

    let mut spec = ConsoleSpec::empty();

    // Split on comma to separate device from baud rate
    let (device, baud_str) = match arg.find(',') {
        Some(pos) => (&arg[..pos], Some(&arg[pos + 1..])),
        None => (arg, None),
    };

    // Copy device name
    let device_bytes = device.as_bytes();
    let len = device_bytes.len().min(spec.device.len());
    spec.device[..len].copy_from_slice(&device_bytes[..len]);
    spec.device_len = len;

    // Parse baud rate if present
    if let Some(baud) = baud_str {
        spec.baud_rate = parse_baud_rate(baud);
    }

    let idx = console.count;
    console.specs[idx] = spec;
    console.count += 1;
}

/// Parse baud rate string (e.g., "115200", "9600n8")
fn parse_baud_rate(s: &str) -> u32 {
    // Take digits only (ignore parity/bits suffix like "n8")
    let digits: &str = s.split(|c: char| !c.is_ascii_digit()).next().unwrap_or("");
    let mut result = 0u32;
    for c in digits.chars() {
        if let Some(digit) = c.to_digit(10) {
            result = result.saturating_mul(10).saturating_add(digit);
        }
    }
    result
}

/// Check if a console device was specified on the command line
pub fn is_cmdline_console(name: &str) -> bool {
    let console = CMDLINE_CONSOLE.lock();
    for i in 0..console.count {
        if console.specs[i].matches(name) {
            return true;
        }
    }
    false
}

/// Get the number of console specifications
#[allow(dead_code)]
pub fn cmdline_console_count() -> usize {
    CMDLINE_CONSOLE.lock().count
}

/// Get a console specification by index
///
/// Returns None if index is out of bounds
#[allow(dead_code)]
pub fn get_cmdline_console(index: usize) -> Option<ConsoleSpec> {
    let console = CMDLINE_CONSOLE.lock();
    if index < console.count {
        Some(console.specs[index])
    } else {
        None
    }
}

/// Get the primary (last specified) console device name
///
/// Returns None if no console= was specified
#[allow(dead_code)]
pub fn primary_cmdline_console() -> Option<ConsoleSpec> {
    let console = CMDLINE_CONSOLE.lock();
    if console.count > 0 {
        Some(console.specs[console.count - 1])
    } else {
        None
    }
}
