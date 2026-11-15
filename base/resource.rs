//! I/O port resources (Linux kernel/resource.c: ioport_resource,
//! request_region, release_region, /proc/ioports)
//!
//! A tree of ranges under the root `PCI IO` [0, 0xffff]: each child
//! lies within its parent, siblings are disjoint and in address order.
//! A driver claims the registers it drives with [`request_region`] (a
//! busy range); one that overlaps a busy range is refused (EBUSY),
//! one inside a range that is not busy (a bus window) goes below it.
//! The architecture claims the legacy ranges at boot (x86
//! reserve_standard_io_resources).
//!
//! Locking: `IOPORT` is a spin RwLock leaf (Linux resource_lock), thread
//! context only; a new range is allocated before it is taken, and the
//! tree is relinked under it, nothing allocated or freed there.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::sync::spin::RwLock;
use crate::util::error::KernelError;

/// Linux IORESOURCE_BUSY: a driver drives this range
const BUSY: u32 = 1 << 31;

/// One range (Linux struct resource: child and sibling links, so
/// inserting and removing under the lock only relinks)
struct Resource {
    start: u64,
    end: u64,
    name: &'static str,
    flags: u32,
    /// First sub-range; they are disjoint and by start
    child: Option<Box<Resource>>,
    /// Next range at this level
    sibling: Option<Box<Resource>>,
}

impl Resource {
    const fn root(name: &'static str, end: u64) -> Self {
        Self {
            start: 0,
            end,
            name,
            flags: 0,
            child: None,
            sibling: None,
        }
    }

    /// Insert `new` somewhere below this range (Linux __request_region's
    /// loop over __request_resource): into the first child it overlaps
    /// that is not busy and contains it, else among the children if it
    /// overlaps none; a busy overlap refuses it (handed back)
    fn insert(&mut self, mut new: Box<Resource>) -> Result<(), Box<Resource>> {
        // Where, found by reading, then linked
        let (mut at, mut into) = (0, false);
        let mut cur = self.child.as_deref();
        while let Some(c) = cur {
            if c.end < new.start {
                at += 1;
                cur = c.sibling.as_deref();
                continue;
            }
            if c.start <= new.end {
                // Overlaps `c`: only a container that holds it takes it
                if c.flags & BUSY != 0 || c.start > new.start || new.end > c.end {
                    return Err(new);
                }
                into = true;
            }
            break;
        }
        let link = self.link_at(at);
        match link {
            Some(c) if into => c.insert(new),
            _ => {
                new.sibling = link.take();
                *link = Some(new);
                Ok(())
            }
        }
    }

    /// The link to the `n`th child (`child` for 0); there are at least
    /// `n` children
    fn link_at(&mut self, n: usize) -> &mut Option<Box<Resource>> {
        let mut link = &mut self.child;
        for _ in 0..n {
            link = &mut link.as_mut().expect("resource: fewer children").sibling;
        }
        link
    }

    /// Unlink the busy range exactly [start, end] below this one (Linux
    /// __release_region)
    fn remove(&mut self, start: u64, end: u64) -> Option<Box<Resource>> {
        let (mut at, mut exact) = (0, false);
        let mut cur = self.child.as_deref();
        while let Some(c) = cur {
            if c.start == start && c.end == end && c.flags & BUSY != 0 {
                exact = true;
                break;
            }
            if c.start <= start && end <= c.end {
                break;
            }
            at += 1;
            cur = c.sibling.as_deref();
        }
        cur?;
        let link = self.link_at(at);
        if exact {
            let mut gone = link.take()?;
            *link = gone.sibling.take();
            Some(gone)
        } else {
            link.as_mut()?.remove(start, end)
        }
    }

    /// /proc/ioports' lines for the children, `depth` deep (Linux
    /// r_show: two spaces a level, `width` hex digits, the range shown
    /// only to CAP_SYS_ADMIN)
    fn show(&self, depth: usize, width: usize, admin: bool, out: &mut Vec<u8>) {
        use core::fmt::Write;
        let mut c = self.child.as_deref();
        while let Some(r) = c {
            let (s, e) = if admin { (r.start, r.end) } else { (0, 0) };
            let mut line = alloc::string::String::new();
            let _ = writeln!(
                line,
                "{:indent$}{s:0width$x}-{e:0width$x} : {}",
                "",
                r.name,
                indent = depth * 2
            );
            out.extend_from_slice(line.as_bytes());
            r.show(depth + 1, width, admin, out);
            c = r.sibling.as_deref();
        }
    }
}

/// Linux ioport_resource
static IOPORT: RwLock<Resource> = RwLock::new(Resource::root("PCI IO", 0xffff));

/// Claim the I/O ports [start, start + n) for `name` (Linux
/// request_region); EBUSY if a busy range overlaps them, ENOMEM
pub fn request_region(start: u64, n: u64, name: &'static str) -> Result<(), KernelError> {
    if n == 0 || start.checked_add(n - 1).is_none_or(|e| e > 0xffff) {
        return Err(KernelError::InvalidArgument);
    }
    let new = crate::util::kalloc::try_box(Resource {
        start,
        end: start + n - 1,
        name,
        flags: BUSY,
        child: None,
        sibling: None,
    })?;
    let r = IOPORT.write().insert(new);
    // A refused range goes after the lock
    r.map_err(|_| KernelError::Busy)
}

/// Give back the I/O ports [start, start + n) a [`request_region`]
/// claimed (Linux release_region)
pub fn release_region(start: u64, n: u64) {
    let gone = IOPORT.write().remove(start, start + n - 1);
    drop(gone);
}

/// /proc/ioports (Linux ioports_proc_show)
pub fn proc_ioports() -> Vec<u8> {
    let admin = crate::task::capable(crate::task::CAP_SYS_ADMIN);
    let mut out = Vec::new();
    IOPORT.read().show(0, 4, admin, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(start: u64, end: u64, flags: u32) -> Box<Resource> {
        Box::new(Resource {
            start,
            end,
            name: "t",
            flags,
            child: None,
            sibling: None,
        })
    }

    fn starts(r: &Resource) -> Vec<u64> {
        let mut v = Vec::new();
        let mut c = r.child.as_deref();
        while let Some(x) = c {
            v.push(x.start);
            c = x.sibling.as_deref();
        }
        v
    }

    /// A busy overlap refuses, a container takes a range inside it, and
    /// a released range frees its place
    #[test]
    fn insert_and_release() {
        let mut root = Resource::root("io", 0xffff);
        assert!(root.insert(res(0x3f8, 0x3ff, BUSY)).is_ok());
        assert!(root.insert(res(0x3f0, 0x3f8, BUSY)).is_err());
        assert!(root.insert(res(0x2f8, 0x2ff, BUSY)).is_ok());
        assert!(root.insert(res(0x1000, 0x1fff, 0)).is_ok());
        assert_eq!(starts(&root), [0x2f8, 0x3f8, 0x1000]);
        assert!(root.insert(res(0x1100, 0x110f, BUSY)).is_ok());
        assert_eq!(starts(&root), [0x2f8, 0x3f8, 0x1000]);
        assert!(root.remove(0x3f8, 0x3ff).is_some());
        assert!(root.insert(res(0x3f0, 0x3f8, BUSY)).is_ok());
        assert!(root.remove(0x1100, 0x110f).is_some());
        assert!(root.remove(0x1100, 0x110f).is_none());
    }
}
