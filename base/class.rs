//! Device classes (Linux drivers/base/class.c): /sys/class/<name>
//! holds a link to each device of the class.

use alloc::sync::Arc;
use alloc::vec::Vec;

use spin::Once;

use super::core::{DevNode, Device};
use crate::fs::kernfs::KNode;
use crate::fs::sysfs;
use crate::sync::spin::Mutex;

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
    dir: Once<Arc<KNode>>,
    /// Registered devices (Linux klist_devices)
    devices: Mutex<Vec<Arc<Device>>>,
}

impl Class {
    pub const fn new(name: &'static str, devnode: Option<fn(&Device) -> Option<DevNode>>) -> Self {
        Self {
            name,
            devnode,
            blk: false,
            dir: Once::new(),
            devices: Mutex::new(Vec::new()),
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

    pub(super) fn add_device(&self, d: Arc<Device>) {
        self.devices.lock().push(d);
    }

    pub(super) fn remove_device(&self, d: &Device) {
        self.devices
            .lock()
            .retain(|x| !core::ptr::eq(Arc::as_ptr(x), d));
    }

    /// Devices of the class (Linux class_for_each_device)
    pub fn devices(&self) -> Vec<Arc<Device>> {
        self.devices.lock().clone()
    }
}
