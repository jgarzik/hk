//! Device tree parsing and management
//!
//! This module provides Flattened Device Tree (FDT) parsing
//! and a device registry for hardware discovery.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub mod registry;

use registry::{DeviceInfo, DeviceRegistry};

/// FDT magic number
const FDT_MAGIC: u32 = 0xd00dfeed;

/// FDT structure block tokens
const FDT_BEGIN_NODE: u32 = 0x00000001;
const FDT_END_NODE: u32 = 0x00000002;
const FDT_PROP: u32 = 0x00000003;
const FDT_NOP: u32 = 0x00000004;
const FDT_END: u32 = 0x00000009;

/// Error types for FDT parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtError {
    /// Invalid magic number
    BadMagic,
    /// Invalid version
    BadVersion,
    /// Data is truncated
    Truncated,
    /// Invalid structure
    InvalidStructure,
    /// Invalid string reference
    InvalidString,
}

/// Parsed device tree - contains metadata for parsing
#[derive(Clone, Copy)]
struct FdtInfo {
    struct_offset: usize,
    struct_size: usize,
    strings_offset: usize,
}

/// Parsed device tree
pub struct DeviceTree<'a> {
    data: &'a [u8],
    info: FdtInfo,
}

impl<'a> DeviceTree<'a> {
    /// Parse a Flattened Device Tree blob
    pub fn from_fdt(data: &'a [u8]) -> Result<Self, DtError> {
        if data.len() < 40 {
            return Err(DtError::Truncated);
        }

        // Parse header (big-endian)
        let magic = read_be32(data, 0);
        if magic != FDT_MAGIC {
            return Err(DtError::BadMagic);
        }

        let totalsize = read_be32(data, 4) as usize;
        if data.len() < totalsize {
            return Err(DtError::Truncated);
        }

        let struct_offset = read_be32(data, 8) as usize;
        let strings_offset = read_be32(data, 12) as usize;
        let version = read_be32(data, 20);
        let struct_size = read_be32(data, 36) as usize;

        // We support version 17 (the common one)
        if version < 17 {
            return Err(DtError::BadVersion);
        }

        let info = FdtInfo {
            struct_offset,
            struct_size,
            strings_offset,
        };

        Ok(Self { data, info })
    }

    /// Get the root node
    pub fn root(&self) -> Option<Node<'a>> {
        let mut offset = self.info.struct_offset;

        // Skip any NOPs at the start
        while offset < self.info.struct_offset + self.info.struct_size {
            let token = read_be32(self.data, offset);
            if token == FDT_NOP {
                offset += 4;
                continue;
            }
            if token == FDT_BEGIN_NODE {
                return Some(Node {
                    data: self.data,
                    info: self.info,
                    offset,
                    depth: 0,
                });
            }
            break;
        }
        None
    }

    /// Find a node by path (e.g., "/serial@3f8")
    pub fn find_node(&self, path: &str) -> Option<Node<'a>> {
        if path.is_empty() || path == "/" {
            return self.root();
        }

        let path = path.strip_prefix('/').unwrap_or(path);
        let mut current = self.root()?;

        for component in path.split('/') {
            if component.is_empty() {
                continue;
            }
            current = current.children().find(|child| {
                let name = child.name();
                name == component || name.split('@').next() == Some(component)
            })?;
        }

        Some(current)
    }

    /// Find all nodes with a given compatible string
    pub fn find_compatible(&self, compatible: &str) -> Vec<Node<'a>> {
        let mut result = Vec::new();
        if let Some(root) = self.root() {
            find_compatible_recursive(&root, compatible, &mut result);
        }
        result
    }

    /// Get the chosen/stdout-path property
    pub fn chosen_stdout_path(&self) -> Option<&'a str> {
        let chosen = self.find_node("/chosen")?;
        let prop = chosen.property("stdout-path")?;
        prop.as_str()
    }

    /// Build a device registry from this device tree
    pub fn build_registry(&self) -> DeviceRegistry {
        let mut registry = DeviceRegistry::new();

        if let Some(root) = self.root() {
            build_registry_recursive(&root, String::new(), &mut registry);
        }

        registry
    }
}

fn find_compatible_recursive<'a>(node: &Node<'a>, compatible: &str, result: &mut Vec<Node<'a>>) {
    if let Some(compat) = node.compatible() {
        // Compatible can have multiple null-separated strings
        for c in compat.split('\0') {
            if c == compatible {
                result.push(*node);
                break;
            }
        }
    }

    for child in node.children() {
        find_compatible_recursive(&child, compatible, result);
    }
}

fn build_registry_recursive(node: &Node<'_>, path: String, registry: &mut DeviceRegistry) {
    let name = node.name();
    let node_path = if path.is_empty() || path == "/" {
        format!("/{}", name)
    } else {
        format!("{}/{}", path, name)
    };

    // Only add nodes that have a compatible property
    if let Some(compatible) = node.compatible() {
        // Take the first compatible string
        let compat = compatible.split('\0').next().unwrap_or("");

        let (base_addr, size) = node.reg().unwrap_or((None, None));
        let interrupts = node.interrupts();
        let clock_frequency = node.clock_frequency();

        let info = DeviceInfo {
            name: String::from(name),
            compatible: String::from(compat),
            base_addr,
            size,
            interrupts,
            clock_frequency,
        };

        registry.add(node_path.clone(), info);
    }

    // Recurse into children
    let child_path = if name.is_empty() {
        String::new()
    } else {
        node_path
    };
    for child in node.children() {
        build_registry_recursive(&child, child_path.clone(), registry);
    }
}

/// A node in the device tree
#[derive(Clone, Copy)]
pub struct Node<'a> {
    data: &'a [u8],
    info: FdtInfo,
    offset: usize,
    depth: usize,
}

impl<'a> Node<'a> {
    /// Get the node name
    pub fn name(&self) -> &'a str {
        // Skip the FDT_BEGIN_NODE token
        let name_start = self.offset + 4;

        // Find null terminator
        let mut name_end = name_start;
        while name_end < self.data.len() && self.data[name_end] != 0 {
            name_end += 1;
        }

        core::str::from_utf8(&self.data[name_start..name_end]).unwrap_or("")
    }

    /// Get a property by name
    pub fn property(&self, name: &str) -> Option<Property<'a>> {
        self.properties().find(|prop| prop.name() == name)
    }

    /// Get the compatible property
    pub fn compatible(&self) -> Option<&'a str> {
        self.property("compatible")?.as_str()
    }

    /// Get the reg property (base_addr, size)
    pub fn reg(&self) -> Option<(Option<u64>, Option<u64>)> {
        let prop = self.property("reg")?;
        let data = prop.data();

        if data.len() >= 8 {
            // Assuming #address-cells = 2, #size-cells = 2
            let addr = Some(read_be64(data, 0));
            let size = if data.len() >= 16 {
                Some(read_be64(data, 8))
            } else if data.len() >= 12 {
                Some(read_be32(data, 8) as u64)
            } else {
                None
            };
            Some((addr, size))
        } else if data.len() >= 4 {
            // Simple case: 32-bit address only
            Some((Some(read_be32(data, 0) as u64), None))
        } else {
            None
        }
    }

    /// Get the interrupts property
    pub fn interrupts(&self) -> Option<Vec<u32>> {
        let prop = self.property("interrupts")?;
        let data = prop.data();

        let count = data.len() / 4;
        let mut result = Vec::with_capacity(count);

        for i in 0..count {
            result.push(read_be32(data, i * 4));
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    /// Get the clock-frequency property
    pub fn clock_frequency(&self) -> Option<u32> {
        let prop = self.property("clock-frequency")?;
        let data = prop.data();
        if data.len() >= 4 {
            Some(read_be32(data, 0))
        } else {
            None
        }
    }

    /// Iterate over properties of this node
    pub fn properties(&self) -> PropertyIter<'a> {
        // Skip BEGIN_NODE token and name (including null terminator and padding)
        let name_start = self.offset + 4;
        let mut name_end = name_start;
        while name_end < self.data.len() && self.data[name_end] != 0 {
            name_end += 1;
        }
        // Skip null terminator and align to 4 bytes
        let props_start = align4(name_end + 1);

        PropertyIter {
            data: self.data,
            info: self.info,
            offset: props_start,
        }
    }

    /// Iterate over children of this node
    pub fn children(&self) -> ChildIter<'a> {
        // Skip BEGIN_NODE token and name
        let name_start = self.offset + 4;
        let mut name_end = name_start;
        while name_end < self.data.len() && self.data[name_end] != 0 {
            name_end += 1;
        }
        let mut offset = align4(name_end + 1);

        // Skip properties
        while offset < self.info.struct_offset + self.info.struct_size {
            let token = read_be32(self.data, offset);
            match token {
                FDT_PROP => {
                    let len = read_be32(self.data, offset + 4) as usize;
                    offset = align4(offset + 12 + len);
                }
                FDT_NOP => {
                    offset += 4;
                }
                _ => break,
            }
        }

        ChildIter {
            data: self.data,
            info: self.info,
            offset,
            depth: self.depth + 1,
        }
    }
}

/// A property in a device tree node
#[derive(Clone, Copy)]
pub struct Property<'a> {
    data: &'a [u8],
    info: FdtInfo,
    offset: usize,
}

impl<'a> Property<'a> {
    /// Get the property name
    pub fn name(&self) -> &'a str {
        let name_offset = read_be32(self.data, self.offset + 8);
        let start = self.info.strings_offset + name_offset as usize;
        if start >= self.data.len() {
            return "";
        }

        // Find null terminator
        let mut end = start;
        while end < self.data.len() && self.data[end] != 0 {
            end += 1;
        }

        core::str::from_utf8(&self.data[start..end]).unwrap_or("")
    }

    /// Get the property data
    pub fn data(&self) -> &'a [u8] {
        let len = read_be32(self.data, self.offset + 4) as usize;
        let data_start = self.offset + 12;
        &self.data[data_start..data_start + len]
    }

    /// Try to interpret as a string
    pub fn as_str(&self) -> Option<&'a str> {
        let data = self.data();
        // Remove trailing null if present
        let data = if data.last() == Some(&0) {
            &data[..data.len() - 1]
        } else {
            data
        };
        core::str::from_utf8(data).ok()
    }

    /// Try to interpret as a u32
    pub fn as_u32(&self) -> Option<u32> {
        let data = self.data();
        if data.len() >= 4 {
            Some(read_be32(data, 0))
        } else {
            None
        }
    }

    /// Try to interpret as a u64
    pub fn as_u64(&self) -> Option<u64> {
        let data = self.data();
        if data.len() >= 8 {
            Some(read_be64(data, 0))
        } else {
            None
        }
    }
}

/// Iterator over properties
pub struct PropertyIter<'a> {
    data: &'a [u8],
    info: FdtInfo,
    offset: usize,
}

impl<'a> Iterator for PropertyIter<'a> {
    type Item = Property<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.offset >= self.info.struct_offset + self.info.struct_size {
                return None;
            }

            let token = read_be32(self.data, self.offset);
            match token {
                FDT_PROP => {
                    let prop = Property {
                        data: self.data,
                        info: self.info,
                        offset: self.offset,
                    };
                    let len = read_be32(self.data, self.offset + 4) as usize;
                    self.offset = align4(self.offset + 12 + len);
                    return Some(prop);
                }
                FDT_NOP => {
                    self.offset += 4;
                }
                _ => return None,
            }
        }
    }
}

/// Iterator over child nodes
pub struct ChildIter<'a> {
    data: &'a [u8],
    info: FdtInfo,
    offset: usize,
    depth: usize,
}

impl<'a> Iterator for ChildIter<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.offset >= self.info.struct_offset + self.info.struct_size {
                return None;
            }

            let token = read_be32(self.data, self.offset);
            match token {
                FDT_BEGIN_NODE => {
                    let node = Node {
                        data: self.data,
                        info: self.info,
                        offset: self.offset,
                        depth: self.depth,
                    };
                    // Advance past this node entirely
                    self.offset = skip_node(self.data, &self.info, self.offset);
                    return Some(node);
                }
                FDT_NOP => {
                    self.offset += 4;
                }
                FDT_END_NODE | FDT_END => {
                    return None;
                }
                _ => {
                    // Unexpected token
                    return None;
                }
            }
        }
    }
}

/// Skip over an entire node (including all children)
fn skip_node(data: &[u8], info: &FdtInfo, mut offset: usize) -> usize {
    // Skip BEGIN_NODE token
    offset += 4;

    // Skip name
    while offset < data.len() && data[offset] != 0 {
        offset += 1;
    }
    offset = align4(offset + 1);

    let mut depth = 1;
    while depth > 0 && offset < info.struct_offset + info.struct_size {
        let token = read_be32(data, offset);
        match token {
            FDT_BEGIN_NODE => {
                depth += 1;
                offset += 4;
                // Skip name
                while offset < data.len() && data[offset] != 0 {
                    offset += 1;
                }
                offset = align4(offset + 1);
            }
            FDT_END_NODE => {
                depth -= 1;
                offset += 4;
            }
            FDT_PROP => {
                let len = read_be32(data, offset + 4) as usize;
                offset = align4(offset + 12 + len);
            }
            FDT_NOP => {
                offset += 4;
            }
            FDT_END => {
                break;
            }
            _ => {
                offset += 4;
            }
        }
    }
    offset
}

/// Read a big-endian u32
fn read_be32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Read a big-endian u64
fn read_be64(data: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Align to 4-byte boundary
fn align4(n: usize) -> usize {
    (n + 3) & !3
}
