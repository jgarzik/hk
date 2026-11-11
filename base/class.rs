//! Device classes (Linux drivers/base/class.c): /sys/class/<name>
//! holds a link to each device of the class.

use alloc::sync::Arc;

use spin::Once;

use super::core::{DevNode, Device};
use crate::fs::kernfs::KNode;
use crate::fs::kernfs::sysfs;

static CLASS_DIR: Once<Arc<KNode>> = Once::new();

/// Linux classes_init: /sys/class
pub fn classes_init() {
    CLASS_DIR.call_once(|| sysfs::top_dir(b"class"));
}

/// A device class (Linux struct class)
pub struct Class {
    pub name: &'static str,
    /// Device node name and mode (Linux class->devnode)
    pub devnode: Option<fn(&Device) -> Option<DevNode>>,
    /// Devices are block devices (/sys/dev/block)
    pub blk: bool,
    /// Class variables of a device's uevents (Linux class->dev_uevent
    /// and device_type->uevent)
    pub uevent: Option<super::bus::UeventFn>,
    dir: Once<Arc<KNode>>,
}

impl Class {
    pub const fn new(name: &'static str, devnode: Option<fn(&Device) -> Option<DevNode>>) -> Self {
        Self {
            name,
            devnode,
            blk: false,
            uevent: None,
            dir: Once::new(),
        }
    }

    /// A class whose devices' uevents get `uevent`'s variables
    pub const fn with_uevent(name: &'static str, uevent: super::bus::UeventFn) -> Self {
        Self {
            name,
            devnode: None,
            blk: false,
            uevent: Some(uevent),
            dir: Once::new(),
        }
    }

    /// A class of block devices
    pub const fn block(name: &'static str, uevent: Option<super::bus::UeventFn>) -> Self {
        Self {
            name,
            devnode: None,
            blk: true,
            uevent,
            dir: Once::new(),
        }
    }

    /// Linux class_register: /sys/class/<name>
    pub fn register(&'static self) {
        self.dir();
    }

    pub fn dir(&self) -> &Arc<KNode> {
        self.dir.call_once(|| {
            let c = CLASS_DIR.get().expect("classes_init");
            c.create_dir(self.name.as_bytes(), 0o755)
                .expect("class directory")
        })
    }
}
