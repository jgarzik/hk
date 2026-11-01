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

use crate::sync::spin::Mutex;
use crate::usb;

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

/// Longest command line kept (Linux COMMAND_LINE_SIZE on x86)
const COMMAND_LINE_SIZE: usize = 2048;

/// The command line, saved at parse time (before the heap exists) for
/// what reads it later: init's arguments (Linux saved_command_line)
static SAVED: Mutex<([u8; COMMAND_LINE_SIZE], usize)> = Mutex::new(([0; COMMAND_LINE_SIZE], 0));

/// The saved command line
pub fn saved() -> alloc::string::String {
    let s = SAVED.lock();
    alloc::string::String::from_utf8_lossy(&s.0[..s.1]).into_owned()
}

/// Parameters the kernel takes itself (Linux: __setup handlers and
/// core params); anything else goes to init
const KERNEL_PARAMS: &[&str] = &[
    "console",
    "earlycon",
    "usb_trace",
    "watchdog_thresh",
    "root",
    "rootfstype",
    "rootwait",
    "ro",
    "rw",
    "quiet",
    "debug",
    "loglevel",
    "panic",
    "init",
    "rdinit",
    "nokaslr",
];

/// What init gets from the command line (Linux init/main.c
/// unknown_bootoption): `rdinit=`, `init=`, words the kernel does not
/// know and without '=' as extra argv, `name=value` ones without a '.'
/// (module parameters) as extra envp; everything after `--` is argv
pub struct InitArgs {
    pub rdinit: Option<alloc::string::String>,
    pub init: Option<alloc::string::String>,
    pub argv: alloc::vec::Vec<alloc::string::String>,
    pub envp: alloc::vec::Vec<alloc::string::String>,
}

/// Split a command line into init's arguments (see [`InitArgs`])
pub fn init_args(cmdline: &str) -> InitArgs {
    use alloc::string::ToString;
    let mut a = InitArgs {
        rdinit: None,
        init: None,
        argv: alloc::vec::Vec::new(),
        envp: alloc::vec::Vec::new(),
    };
    let mut words = cmdline.split_whitespace();
    for w in words.by_ref() {
        if w == "--" {
            break;
        }
        let (name, value) = match w.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (w, None),
        };
        match (name, value) {
            ("rdinit", Some(v)) => a.rdinit = Some(v.to_string()),
            ("init", Some(v)) => a.init = Some(v.to_string()),
            _ if KERNEL_PARAMS.contains(&name) || name.contains('.') => {}
            (_, Some(_)) => a.envp.push(w.to_string()),
            (_, None) => a.argv.push(w.to_string()),
        }
    }
    a.argv.extend(words.map(|w| w.to_string()));
    a
}

/// Parse kernel command line and apply options
///
/// Supported options:
/// - `usb_trace`: Enable USB protocol tracing for debugging
/// - `console=<device>[,<baud>]`: Set kernel console device
/// - `watchdog_thresh=<seconds>`: soft lockup threshold (`watchdog`)
pub fn parse_cmdline(cmdline: &str) {
    {
        let mut s = SAVED.lock();
        let n = cmdline.len().min(COMMAND_LINE_SIZE);
        s.0[..n].copy_from_slice(&cmdline.as_bytes()[..n]);
        s.1 = n;
    }
    for option in cmdline.split_whitespace() {
        if option == "usb_trace" {
            usb::enable_usb_trace();
        } else if let Some(console_arg) = option.strip_prefix("console=") {
            parse_console_option(console_arg);
        } else if let Some(s) = option.strip_prefix("watchdog_thresh=")
            && let Ok(s) = s.parse()
        {
            crate::watchdog::set_thresh(s);
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
    console.specs[..console.count]
        .iter()
        .any(|spec| spec.matches(name))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_args_split() {
        let a = init_args(
            "console=ttyS0 root=/dev/ram0 rdinit=/bin/init single FOO=bar mod.p=1 quiet -- -x y=z",
        );
        assert_eq!(a.rdinit.as_deref(), Some("/bin/init"));
        assert_eq!(a.init, None);
        assert_eq!(a.argv, ["single", "-x", "y=z"]);
        assert_eq!(a.envp, ["FOO=bar"]);
    }
}
