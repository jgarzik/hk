//! Devices (Linux drivers/base/core.c)
//!
//! A `Device` is a directory under /sys/devices: below its parent, or
//! for a class device without one below `virtual/<class>`; a class
//! device with a non-class parent sits in the parent's `<class>` glue
//! directory (Linux get_device_parent). `device_add` creates its
//! `uevent` and `dev` attributes, the `subsystem`/`device` links, the
//! class link, `/sys/dev/{char,block}/M:m` and the devtmpfs node, adds
//! a bus device to its bus, sends the "add" uevent and probes it; `del`
//! unbinds it and sends "remove" first.
//!
//! ## Locking
//!
//! `Device.lock` (sleeping Mutex, Linux device_lock) is held across
//! probe and release; the driver and its state are spin leaves read
//! without it. Bus, class and `DEVICES_LIST` are spin leaves; sysfs
//! changes take kernfs's locks (doc/LOCKING.md 3.3).

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt::Write;

use spin::Once;

use core::any::Any;

use super::bus::BusType;
use super::class::Class;
use super::driver::{Bound, Driver};
use crate::fs::KernelError;
use crate::fs::chardev::DevId;
use crate::fs::kernfs::{self, Attr, KNode, SysBuf};
use crate::fs::sysfs;
use crate::sync::Mutex;
use crate::sync::spin::{Mutex as SpinMutex, RwLock};

static DEVICES: Once<Arc<KNode>> = Once::new();
static DEV_CHAR: Once<Arc<KNode>> = Once::new();
static DEV_BLOCK: Once<Arc<KNode>> = Once::new();
static VIRTUAL: Once<Arc<KNode>> = Once::new();

/// Linux devices_init: /sys/devices, /sys/dev/{block,char}
pub fn devices_init() {
    DEVICES.call_once(|| sysfs::top_dir(b"devices"));
    let dev = sysfs::top_dir(b"dev");
    DEV_BLOCK.call_once(|| dev.create_dir(b"block", 0o755).expect("/sys/dev/block"));
    DEV_CHAR.call_once(|| dev.create_dir(b"char", 0o755).expect("/sys/dev/char"));
}

fn devices_dir() -> &'static Arc<KNode> {
    DEVICES.get().expect("driver_init")
}

/// /sys/devices/virtual (Linux virtual_device_parent)
fn virtual_dir() -> &'static Arc<KNode> {
    VIRTUAL.call_once(|| {
        devices_dir()
            .create_dir(b"virtual", 0o755)
            .expect("/sys/devices/virtual")
    })
}

/// Directory `name` below `parent`, made if missing
fn dir_in(parent: &Arc<KNode>, name: &[u8]) -> Result<Arc<KNode>, KernelError> {
    match parent.create_dir(name, 0o755) {
        Err(KernelError::AlreadyExists) => parent.find(name).ok_or(KernelError::NotFound),
        r => r,
    }
}

/// A device node's name below /dev and its mode (0: devtmpfs default)
pub struct DevNode {
    pub name: String,
    pub mode: u16,
}

/// Bus-specific data of a device (Linux: the structure embedding it)
pub type DevData = Arc<dyn Any + Send + Sync>;

/// What `device_create` registers
pub struct DeviceInfo<'a> {
    pub name: String,
    pub parent: Option<&'a Arc<Device>>,
    pub bus: Option<&'static BusType>,
    pub class: Option<&'static Class>,
    pub devt: Option<DevId>,
    /// DEVTYPE (Linux device_type.name)
    pub devtype: Option<&'static str>,
    pub data: Option<DevData>,
}

impl DeviceInfo<'_> {
    /// A device `name` with nothing else set
    pub fn named(name: &str) -> Self {
        Self {
            name: name.into(),
            parent: None,
            bus: None,
            class: None,
            devt: None,
            devtype: None,
            data: None,
        }
    }
}

/// Every registered device, parents before children (Linux
/// devices_kset list)
static DEVICES_LIST: SpinMutex<Vec<Arc<Device>>> = SpinMutex::new(Vec::new());

/// A device (Linux struct device)
pub struct Device {
    name: String,
    parent: Option<Arc<Device>>,
    pub bus: Option<&'static BusType>,
    pub class: Option<&'static Class>,
    pub devt: Option<DevId>,
    pub devtype: Option<&'static str>,
    data: Option<DevData>,
    kobj: Once<Arc<KNode>>,
    /// Linux device_lock
    pub lock: Mutex<()>,
    driver: RwLock<Option<&'static Driver>>,
    /// The bound driver's state (Linux drvdata)
    bound: SpinMutex<Option<Arc<dyn Bound>>>,
    me: Weak<Device>,
}

/// The `uevent` attribute: the device's environment (Linux
/// uevent_show); a write sends a synthetic event (uevent_store)
struct UeventAttr(Weak<Device>);

impl Attr for UeventAttr {
    fn show(&self, out: &mut SysBuf) -> Result<(), KernelError> {
        if let Some(d) = self.0.upgrade() {
            for kv in d.uevent_env() {
                out.bytes(&kv);
                out.bytes(b"\n");
            }
        }
        Ok(())
    }

    fn store(&self, data: &[u8]) -> Result<usize, KernelError> {
        let d = self.0.upgrade().ok_or(KernelError::NoDevice)?;
        super::uevent::synth_uevent(&d, data)?;
        Ok(data.len())
    }
}

impl Device {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn parent(&self) -> Option<&Arc<Device>> {
        self.parent.as_ref()
    }

    /// The device's sysfs directory (registered devices only)
    pub fn kobj(&self) -> &Arc<KNode> {
        self.kobj.get().expect("device registered")
    }

    /// Path below /sys (DEVPATH)
    pub fn devpath(&self) -> Vec<u8> {
        self.kobj().path()
    }

    /// devtmpfs name and mode (Linux device_get_devnode)
    pub fn devnode(&self) -> DevNode {
        if let Some(f) = self.class.and_then(|c| c.devnode)
            && let Some(n) = f(self)
        {
            return n;
        }
        DevNode {
            name: self.name.replace('!', "/"),
            mode: 0,
        }
    }

    /// SUBSYSTEM of its uevents: the bus, else the class (Linux
    /// dev_uevent_name)
    pub fn subsystem(&self) -> Option<&'static str> {
        self.bus.map(|b| b.name).or(self.class.map(|c| c.name))
    }

    /// The bus-specific data, if it is a `T`
    pub fn data<T: 'static>(&self) -> Option<&T> {
        self.data.as_ref()?.downcast_ref::<T>()
    }

    pub fn driver(&self) -> Option<&'static Driver> {
        *self.driver.read()
    }

    pub(super) fn set_driver(&self, d: Option<&'static Driver>) {
        *self.driver.write() = d;
    }

    /// Install or take the bound driver's state
    pub(super) fn set_bound(&self, b: Option<Arc<dyn Bound>>) -> Option<Arc<dyn Bound>> {
        core::mem::replace(&mut *self.bound.lock(), b)
    }

    /// The bound driver's state (Linux dev_get_drvdata)
    pub fn drvdata(&self) -> Option<Arc<dyn Bound>> {
        self.bound.lock().clone()
    }

    fn is_blk(&self) -> bool {
        self.class.is_some_and(|c| c.blk)
    }

    /// Environment of the device's uevents (Linux dev_uevent)
    pub fn uevent_env(&self) -> Vec<Vec<u8>> {
        let mut env = Vec::new();
        let mut kv = |args: core::fmt::Arguments| {
            let mut s = String::new();
            let _ = s.write_fmt(args);
            env.push(s.into_bytes());
        };
        if let Some(dt) = self.devt {
            kv(format_args!("MAJOR={}", dt.major));
            kv(format_args!("MINOR={}", dt.minor));
            let n = self.devnode();
            kv(format_args!("DEVNAME={}", n.name));
            if n.mode != 0 {
                kv(format_args!("DEVMODE=0{:o}", n.mode));
            }
        }
        if let Some(t) = self.devtype {
            kv(format_args!("DEVTYPE={}", t));
        }
        if let Some(d) = self.driver() {
            kv(format_args!("DRIVER={}", d.name));
        }
        if let Some(f) = self.bus.and_then(|b| b.uevent) {
            f(self, &mut env);
        }
        env
    }

    /// Add attribute `name` to the device's directory
    pub fn create_file(
        &self,
        name: &[u8],
        mode: u16,
        attr: Arc<dyn Attr>,
    ) -> Result<Arc<KNode>, KernelError> {
        self.kobj().create_file(name, mode, attr)
    }

    /// Where the device's directory goes (Linux get_device_parent)
    fn parent_dir(&self) -> Result<Arc<KNode>, KernelError> {
        match (self.class, &self.parent) {
            (Some(c), None) => dir_in(virtual_dir(), c.name.as_bytes()),
            (Some(c), Some(p)) if p.class.is_none() => dir_in(p.kobj(), c.name.as_bytes()),
            (_, Some(p)) => Ok(p.kobj().clone()),
            (None, None) => Ok(devices_dir().clone()),
        }
    }

    fn sys_dev_dir(&self) -> &'static Arc<KNode> {
        if self.is_blk() {
            DEV_BLOCK.get().expect("driver_init")
        } else {
            DEV_CHAR.get().expect("driver_init")
        }
    }

    /// Linux device_add (sysfs and devtmpfs parts)
    fn add(&self) -> Result<(), KernelError> {
        let dir = self.parent_dir()?.create_dir(self.name.as_bytes(), 0o755)?;
        self.kobj.call_once(|| dir.clone());
        dir.create_file(b"uevent", 0o644, Arc::new(UeventAttr(self.me.clone())))?;
        if let Some(c) = self.class {
            let cdir = c.dir();
            dir.create_link(b"subsystem", cdir)?;
            cdir.create_link(self.name.as_bytes(), &dir)?;
            if let Some(p) = &self.parent {
                dir.create_link(b"device", p.kobj())?;
            }
            c.add_device(self.me.upgrade().expect("device alive"));
        }
        if let Some(dt) = self.devt {
            dir.create_file(
                b"dev",
                0o444,
                kernfs::show(move |o| {
                    let _ = writeln!(o, "{}:{}", dt.major, dt.minor);
                }),
            )?;
            let mm = alloc::format!("{}:{}", dt.major, dt.minor);
            self.sys_dev_dir().create_link(mm.as_bytes(), &dir)?;
            let n = self.devnode();
            let mode = if n.mode != 0 { n.mode } else { 0o600 };
            crate::fs::devtmpfs::device_add(&n.name, dt, self.is_blk(), mode);
        }
        let me = self.me.upgrade().expect("device alive");
        if let Some(b) = self.bus {
            b.add_device(&me)?;
        }
        DEVICES_LIST.lock().push(me.clone());
        super::uevent::uevent(self, super::uevent::Action::Add);
        if self.bus.is_some_and(|b| b.autoprobe()) {
            super::dd::device_attach(&me);
        }
        Ok(())
    }

    /// Linux device_del: unbind, then undo `device_add`
    pub fn del(self: &Arc<Self>) {
        let Some(dir) = self.kobj.get() else { return };
        if let Some(b) = self.bus {
            super::dd::device_release_driver(self);
            b.remove_device(self);
        }
        DEVICES_LIST.lock().retain(|d| !Arc::ptr_eq(d, self));
        super::uevent::uevent(self, super::uevent::Action::Remove);
        if let Some(dt) = self.devt {
            crate::fs::devtmpfs::device_del(&self.devnode().name);
            let mm = alloc::format!("{}:{}", dt.major, dt.minor);
            self.sys_dev_dir().remove_child(mm.as_bytes());
        }
        if let Some(c) = self.class {
            c.dir().remove_child(self.name.as_bytes());
            c.remove_device(self);
        }
        let glue = dir.parent();
        dir.remove();
        // An emptied class glue directory goes too (cleanup_glue_dir)
        if let (Some(g), Some(c)) = (glue, self.class)
            && g.name() == c.name.as_bytes()
            && g.list_from(0).is_empty()
        {
            g.remove();
        }
    }
}

/// Create and register a device (Linux device_create)
pub fn device_create(info: DeviceInfo) -> Result<Arc<Device>, KernelError> {
    let d = Arc::new_cyclic(|me| Device {
        name: info.name,
        parent: info.parent.cloned(),
        bus: info.bus,
        class: info.class,
        devt: info.devt,
        devtype: info.devtype,
        data: info.data,
        kobj: Once::new(),
        lock: Mutex::new(()),
        driver: RwLock::new(None),
        bound: SpinMutex::new(None),
        me: me.clone(),
    });
    if let Err(e) = d.add() {
        d.del();
        return Err(e);
    }
    Ok(d)
}

/// Quiesce every bound device before power-off, restart or halt, the
/// last registered first (Linux device_shutdown); runs once
pub fn device_shutdown() {
    let devs = core::mem::take(&mut *DEVICES_LIST.lock());
    for d in devs.iter().rev() {
        let b = d.bound.lock().clone();
        if let Some(b) = b {
            b.shutdown();
        }
    }
    // The devices stay registered: the machine goes down next
    core::mem::forget(devs);
}
