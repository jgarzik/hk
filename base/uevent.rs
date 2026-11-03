//! uevents (Linux lib/kobject_uevent.c): device events broadcast on
//! NETLINK_KOBJECT_UEVENT group 1 as "ACTION@DEVPATH\0KEY=VALUE\0...",
//! from port 0 with root credentials, into every network namespace.
//! Writing an action to a device's `uevent` file sends a synthetic
//! event (`kobject_synth_uevent`).

use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::core::Device;
use crate::fs::KernelError;
use crate::ksysfs::UEVENT_SEQNUM;
use crate::net::netlink::{self, NETLINK_KOBJECT_UEVENT, NlSkb};

/// Linux enum kobject_action
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Add,
    Remove,
    Change,
    Move,
    Online,
    Offline,
    Bind,
    Unbind,
}

const ACTIONS: [(Action, &[u8]); 8] = [
    (Action::Add, b"add"),
    (Action::Remove, b"remove"),
    (Action::Change, b"change"),
    (Action::Move, b"move"),
    (Action::Online, b"online"),
    (Action::Offline, b"offline"),
    (Action::Bind, b"bind"),
    (Action::Unbind, b"unbind"),
];

impl Action {
    pub fn name(self) -> &'static [u8] {
        ACTIONS.iter().find(|a| a.0 == self).map_or(b"", |a| a.1)
    }

    fn parse(w: &[u8]) -> Option<Self> {
        ACTIONS.iter().find(|a| a.1 == w).map(|a| a.0)
    }
}

/// Send `action` for `dev` with extra variables `ext` (Linux
/// kobject_uevent_env); devices with neither bus nor class send none
pub fn uevent_env(dev: &Device, action: Action, ext: &[Vec<u8>]) {
    let Some(subsystem) = dev.subsystem() else {
        return;
    };
    send(
        &dev.devpath(),
        subsystem.as_bytes(),
        action,
        ext,
        dev.uevent_env(),
        dev.ns,
    );
}

/// Build and broadcast one event of the object at `devpath`: into
/// namespace `ns` only if tagged, else into every one (Linux
/// kobject_uevent_net_broadcast)
fn send(
    devpath: &[u8],
    subsystem: &[u8],
    action: Action,
    ext: &[Vec<u8>],
    own: Vec<Vec<u8>>,
    ns: u64,
) {
    let mut env: Vec<Vec<u8>> = Vec::new();
    env.push([b"ACTION=", action.name()].concat());
    env.push([b"DEVPATH=", devpath].concat());
    env.push([b"SUBSYSTEM=", subsystem].concat());
    env.extend(ext.iter().cloned());
    env.extend(own);
    if action == Action::Unbind {
        env.retain(|v| !v.starts_with(b"MODALIAS="));
    }
    let seq = UEVENT_SEQNUM.fetch_add(1, Ordering::AcqRel) + 1;
    env.push(format!("SEQNUM={}", seq).into_bytes());
    let mut msg = [action.name(), b"@", devpath, b"\0"].concat();
    for v in &env {
        msg.extend_from_slice(v);
        msg.push(0);
    }
    for net in crate::ns::net::all_net_ns() {
        if ns != 0 && net.id != ns {
            continue;
        }
        netlink::broadcast(
            &net,
            NETLINK_KOBJECT_UEVENT,
            NlSkb::kernel(msg.clone(), 1),
            0,
        );
    }
}

/// Linux kobject_uevent
pub fn uevent(dev: &Device, action: Action) {
    uevent_env(dev, action, &[]);
}

/// Linux uuid_is_valid: 8-4-4-4-12 hex digits
fn uuid_valid(u: &[u8]) -> bool {
    u.len() == 36
        && u.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Linux kobject_action_args: "UUID[ KEY=VALUE]..." with alphanumeric
/// keys and values
fn synth_args(args: &[u8]) -> Option<Vec<Vec<u8>>> {
    if args.len() < 36 || !uuid_valid(&args[..36]) {
        return None;
    }
    let mut env = alloc::vec![[b"SYNTH_UUID=", &args[..36]].concat()];
    let rest = &args[36..];
    if rest.is_empty() {
        return Some(env);
    }
    let rest = rest.strip_prefix(b" ")?;
    for kv in rest.split(|&c| c == b' ') {
        let eq = kv.iter().position(|&c| c == b'=')?;
        let (k, v) = (&kv[..eq], &kv[eq + 1..]);
        let word = |w: &[u8]| !w.is_empty() && w.iter().all(u8::is_ascii_alphanumeric);
        if !word(k) || !word(v) {
            return None;
        }
        env.push([b"SYNTH_ARG_", k, b"=", v].concat());
    }
    Some(env)
}

/// Parse a synthetic event write: the action and SYNTH_* variables
fn synth_parse(buf: &[u8]) -> Result<(Action, Vec<Vec<u8>>), KernelError> {
    let buf = buf
        .strip_suffix(b"\n")
        .or_else(|| buf.strip_suffix(b"\0"))
        .unwrap_or(buf);
    let (word, args) = match buf.iter().position(|&c| c == b' ') {
        Some(i) => (&buf[..i], Some(&buf[i + 1..])),
        None => (buf, None),
    };
    let action = Action::parse(word).ok_or(KernelError::InvalidArgument)?;
    let ext = match args {
        None => alloc::vec![b"SYNTH_UUID=0".to_vec()],
        Some(a) => synth_args(a).ok_or(KernelError::InvalidArgument)?,
    };
    Ok((action, ext))
}

/// Linux kobject_synth_uevent: "action[ UUID[ KEY=VALUE...]]", a
/// trailing newline or NUL ignored; EINVAL if malformed
pub fn synth_uevent(dev: &Device, buf: &[u8]) -> Result<(), KernelError> {
    let (action, ext) = synth_parse(buf)?;
    uevent_env(dev, action, &ext);
    Ok(())
}

/// A synthetic event of a non-device object (a bus or driver
/// directory) at `devpath`
pub fn synth_kobj(devpath: &[u8], subsystem: &[u8], buf: &[u8]) -> Result<(), KernelError> {
    let (action, ext) = synth_parse(buf)?;
    send(devpath, subsystem, action, &ext, Vec::new(), 0);
    Ok(())
}
