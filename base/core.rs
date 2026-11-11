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
//! without it. A bus's device list is a klist (`util::klist`, a spin
//! leaf, walked while devices come and go) and `DEVICES_LIST` an
//! intrusive spin-leaf list: nothing allocates under either. sysfs
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
use crate::fs::kernfs::sysfs;
use crate::fs::kernfs::{self, Attr, KNode, SysBuf};
use crate::sync::Mutex;
use crate::sync::spin::{Mutex as SpinMutex, RwLock};
use crate::util::kalloc::{try_arc, try_arc_cyclic};

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

/// Serializes glue directories' creation and removal (Linux gdp_mutex;
/// sleeping, before KERNFS_RWSEM)
static GLUE: Mutex<()> = Mutex::new(());

/// The parts of a device `add` registered
#[derive(Clone, Copy, Default)]
struct Added {
    dir: bool,
    class_link: bool,
    sys_dev: bool,
    devnode: bool,
    bus: bool,
    listed: bool,
    announced: bool,
}

/// Bus-specific data of a device (Linux: the structure embedding it)
pub type DevData = Arc<dyn Any + Send + Sync>;

/// What `device_create` registers
#[derive(Default)]
pub struct DeviceInfo<'a> {
    pub name: String,
    pub parent: Option<&'a Arc<Device>>,
    pub bus: Option<&'static BusType>,
    pub class: Option<&'static Class>,
    pub devt: Option<DevId>,
    /// DEVTYPE (Linux device_type.name)
    pub devtype: Option<&'static str>,
    pub data: Option<DevData>,
    /// Adds the device's attributes before it is announced (Linux
    /// dev->groups and the bus's dev_groups)
    pub attrs: Option<AttrsFn>,
    /// Network namespace tag of its directory and class link (0: none;
    /// Linux kobject namespace of net devices)
    pub ns: u64,
    /// The directory it goes in when it has no parent device (Linux
    /// dev->kobj.parent set directly: a system subsystem's root below
    /// /sys/devices/system)
    pub dir: Option<Arc<KNode>>,
}

/// Creates a device's attribute files
pub type AttrsFn = fn(&Arc<Device>) -> Result<(), KernelError>;

impl DeviceInfo<'_> {
    /// A device `name` with nothing else set
    pub fn named(name: &str) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }
}

/// Every registered device, parents before children (Linux
/// devices_kset list, linked through `Device.kset_link`)
static DEVICES_LIST: SpinMutex<crate::util::list::ArcList<DevKset>> =
    SpinMutex::new(crate::util::list::ArcList::new());

/// A device (Linux struct device)
pub struct Device {
    name: String,
    parent: Option<Arc<Device>>,
    pub bus: Option<&'static BusType>,
    pub class: Option<&'static Class>,
    pub devt: Option<DevId>,
    pub devtype: Option<&'static str>,
    data: Option<DevData>,
    attrs: Option<AttrsFn>,
    /// Network namespace tag (0: none)
    pub ns: u64,
    /// Explicit directory to go in (no parent device)
    dir: Option<Arc<KNode>>,
    kobj: Once<Arc<KNode>>,
    /// Linux device_lock, guarding "deleted" (Linux p->dead): a dead
    /// device is not bound again
    pub lock: Mutex<bool>,
    /// What `add` registered so far, for `del` and failure unwinding
    added: SpinMutex<Added>,
    driver: RwLock<Option<&'static Driver>>,
    /// The bound driver's state (Linux drvdata)
    bound: SpinMutex<Option<Arc<dyn Bound>>>,
    /// On its bus's device klist (Linux p->knode_bus)
    pub(super) knode_bus: crate::util::klist::KlistNode,
    /// On `DEVICES_LIST` (Linux kobj.entry in devices_kset)
    kset_link: crate::util::list::Link,
    me: Weak<Device>,
}

crate::klist_adapter!(pub DevBus, Device, knode_bus);
crate::adapter!(DevKset, Device, kset_link);

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

    /// The bus-specific data as a shared `T`
    pub fn data_arc<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.data.clone()?.downcast::<T>().ok()
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
        let mut kv = |args: core::fmt::Arguments<'_>| {
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
        if let Some(f) = self.class.and_then(|c| c.uevent) {
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
        if let Some(d) = &self.dir {
            return Ok(d.clone());
        }
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

    /// Linux device_add: each step it completes is recorded, so a
    /// failure undoes exactly those (Linux's error unwinding)
    fn add(&self) -> Result<(), KernelError> {
        let dir = {
            // Glue directories are found or made, and the device's made
            // in one, under GLUE (Linux gdp_mutex)
            let _g = GLUE.lock();
            self.parent_dir()?
                .create_dir_ns(self.name.as_bytes(), 0o755, self.ns)?
        };
        self.kobj.call_once(|| dir.clone());
        self.added.lock().dir = true;
        dir.create_file(b"uevent", 0o644, try_arc(UeventAttr(self.me.clone()))?)?;
        let me = self.me.upgrade().expect("device alive");
        if let Some(c) = self.class {
            let cdir = c.dir();
            dir.create_link(b"subsystem", cdir)?;
            cdir.create_link_ns(self.name.as_bytes(), &dir, self.ns)?;
            self.added.lock().class_link = true;
            if let Some(p) = &self.parent {
                dir.create_link(b"device", p.kobj())?;
            }
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
            self.added.lock().sys_dev = true;
            let n = self.devnode();
            let mode = if n.mode != 0 { n.mode } else { 0o600 };
            crate::fs::ramfs::devtmpfs::device_add(&n.name, dt, self.is_blk(), mode);
            self.added.lock().devnode = true;
        }
        if let Some(f) = self.attrs {
            f(&me)?;
        }
        if let Some(b) = self.bus {
            b.add_device(&me)?;
            self.added.lock().bus = true;
        }
        DEVICES_LIST.lock().push_back(me.clone());
        self.added.lock().listed = true;
        super::uevent::uevent(self, super::uevent::Action::Add);
        self.added.lock().announced = true;
        if self.bus.is_some_and(|b| b.autoprobe()) {
            super::dd::device_attach(&me);
        }
        Ok(())
    }

    /// Linux device_del: marked dead (no new binding), off its bus's
    /// list, unbound, announced gone, then its entries removed
    pub fn del(self: &Arc<Self>) {
        *self.lock.lock() = true;
        let added = *self.added.lock();
        if added.bus
            && let Some(b) = self.bus
        {
            b.remove_device(self);
            self.added.lock().bus = false;
            super::dd::device_release_driver(self);
        }
        if added.announced {
            super::uevent::uevent(self, super::uevent::Action::Remove);
        }
        self.undo();
    }

    /// Remove what `add` made (per `added`), the directory last
    fn undo(self: &Arc<Self>) {
        let a = core::mem::take(&mut *self.added.lock());
        if a.listed {
            let gone = {
                let mut l = DEVICES_LIST.lock();
                // `kset_link` is used only by DEVICES_LIST, so a linked
                // device is on it (device_shutdown may have taken it)
                // SAFETY: as just said
                self.kset_link
                    .is_linked()
                    .then(|| unsafe { l.remove(self) })
            };
            drop(gone);
        }
        if a.bus
            && let Some(b) = self.bus
        {
            b.remove_device(self);
        }
        if let Some(dt) = self.devt {
            if a.devnode {
                crate::fs::ramfs::devtmpfs::device_del(&self.devnode().name);
            }
            if a.sys_dev {
                let mm = alloc::format!("{}:{}", dt.major, dt.minor);
                self.sys_dev_dir().remove_child(mm.as_bytes());
            }
        }
        if let Some(c) = self.class
            && a.class_link
        {
            c.dir().remove_child_ns(self.name.as_bytes(), self.ns);
        }
        if !a.dir {
            return;
        }
        let Some(dir) = self.kobj.get() else { return };
        let _g = GLUE.lock();
        let glue = dir.parent();
        dir.remove();
        // An emptied class glue directory goes too (cleanup_glue_dir)
        if let (Some(g), Some(c)) = (glue, self.class)
            && g.name() == c.name.as_bytes()
            && g.is_empty()
        {
            g.remove();
        }
    }
}

/// Create and register a device (Linux device_create)
pub fn device_create(info: DeviceInfo<'_>) -> Result<Arc<Device>, KernelError> {
    let d = try_arc_cyclic(|me| Device {
        name: info.name,
        parent: info.parent.cloned(),
        bus: info.bus,
        class: info.class,
        devt: info.devt,
        devtype: info.devtype,
        data: info.data,
        attrs: info.attrs,
        ns: info.ns,
        dir: info.dir,
        kobj: Once::new(),
        lock: Mutex::new(false),
        added: SpinMutex::new(Added::default()),
        driver: RwLock::new(None),
        bound: SpinMutex::new(None),
        knode_bus: crate::util::klist::KlistNode::new(),
        kset_link: crate::util::list::Link::new(),
        me: me.clone(),
    })?;
    if let Err(e) = d.add() {
        d.undo();
        return Err(e);
    }
    Ok(d)
}

/// Quiesce every bound device before power-off, restart or halt, the
/// last registered first (Linux device_shutdown); runs once
pub fn device_shutdown() {
    // One at a time off the list's end, with it unlocked (Linux takes
    // devices_kset->list.prev, list_del_init, then shuts it down)
    loop {
        let Some(d) = DEVICES_LIST.lock().pop_back() else {
            break;
        };
        let b = d.bound.lock().clone();
        if let Some(b) = b {
            b.shutdown();
        }
        // The device stays registered: the machine goes down next
        core::mem::forget(d);
    }
}
