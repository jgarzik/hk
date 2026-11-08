//! USB driver matching and uevents (Linux drivers/usb/core/driver.c,
//! include/linux/usb.h id macros): usb_device drivers (the generic
//! one) take usb_device devices, interface drivers take interfaces
//! by their `usb_device_id` table.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{UsbDevice, UsbInterface, class};

/// usb_device_id.match_flags (Linux USB_DEVICE_ID_MATCH_*)
pub mod id_match {
    pub const VENDOR: u16 = 0x0001;
    pub const PRODUCT: u16 = 0x0002;
    pub const DEV_LO: u16 = 0x0004;
    pub const DEV_HI: u16 = 0x0008;
    pub const DEV_CLASS: u16 = 0x0010;
    pub const DEV_SUBCLASS: u16 = 0x0020;
    pub const DEV_PROTOCOL: u16 = 0x0040;
    pub const INT_CLASS: u16 = 0x0080;
    pub const INT_SUBCLASS: u16 = 0x0100;
    pub const INT_PROTOCOL: u16 = 0x0200;
    pub const INT_NUMBER: u16 = 0x0400;
    pub const INT_INFO: u16 = INT_CLASS | INT_SUBCLASS | INT_PROTOCOL;
}

/// One id table entry (Linux struct usb_device_id)
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbDeviceId {
    pub match_flags: u16,
    pub id_vendor: u16,
    pub id_product: u16,
    pub bcd_device_lo: u16,
    pub bcd_device_hi: u16,
    pub b_device_class: u8,
    pub b_device_sub_class: u8,
    pub b_device_protocol: u8,
    pub b_interface_class: u8,
    pub b_interface_sub_class: u8,
    pub b_interface_protocol: u8,
    pub b_interface_number: u8,
}

impl UsbDeviceId {
    const NONE: Self = Self {
        match_flags: 0,
        id_vendor: 0,
        id_product: 0,
        bcd_device_lo: 0,
        bcd_device_hi: 0,
        b_device_class: 0,
        b_device_sub_class: 0,
        b_device_protocol: 0,
        b_interface_class: 0,
        b_interface_sub_class: 0,
        b_interface_protocol: 0,
        b_interface_number: 0,
    };

    /// Linux USB_DEVICE
    pub const fn device(vendor: u16, product: u16) -> Self {
        Self {
            match_flags: id_match::VENDOR | id_match::PRODUCT,
            id_vendor: vendor,
            id_product: product,
            ..Self::NONE
        }
    }

    /// Linux USB_INTERFACE_INFO
    pub const fn interface_info(cl: u8, sc: u8, pr: u8) -> Self {
        Self {
            match_flags: id_match::INT_INFO,
            b_interface_class: cl,
            b_interface_sub_class: sc,
            b_interface_protocol: pr,
            ..Self::NONE
        }
    }

    fn has(&self, f: u16) -> bool {
        self.match_flags & f != 0
    }

    /// Linux usb_match_device
    fn match_device(&self, d: &UsbDevice) -> bool {
        use id_match::*;
        !(self.has(VENDOR) && self.id_vendor != d.vendor_id
            || self.has(PRODUCT) && self.id_product != d.product_id
            || self.has(DEV_LO) && self.bcd_device_lo > d.bcd_device
            || self.has(DEV_HI) && self.bcd_device_hi < d.bcd_device
            || self.has(DEV_CLASS) && self.b_device_class != d.device_class
            || self.has(DEV_SUBCLASS) && self.b_device_sub_class != d.device_subclass
            || self.has(DEV_PROTOCOL) && self.b_device_protocol != d.device_protocol)
    }

    /// Linux usb_match_one_id_intf: interface fields of a
    /// vendor-specific device count only with the vendor matched too
    fn match_intf(&self, d: &UsbDevice, f: &UsbInterface) -> bool {
        use id_match::*;
        if d.device_class == class::VENDOR_SPEC
            && !self.has(VENDOR)
            && self.has(INT_INFO | INT_NUMBER)
        {
            return false;
        }
        !(self.has(INT_CLASS) && self.b_interface_class != f.class
            || self.has(INT_SUBCLASS) && self.b_interface_sub_class != f.subclass
            || self.has(INT_PROTOCOL) && self.b_interface_protocol != f.protocol
            || self.has(INT_NUMBER) && self.b_interface_number != f.number)
    }

    /// Linux usb_match_one_id
    pub fn matches(&self, d: &UsbDevice, f: &UsbInterface) -> bool {
        self.match_device(d) && self.match_intf(d, f)
    }
}

/// A USB driver's ids: a usb_device driver (Linux usb_device_driver;
/// the generic driver takes every device), or an interface driver's
/// id table (Linux usb_driver.id_table)
pub enum UsbIds {
    Device,
    Interface(&'static [UsbDeviceId]),
}

/// Linux usb_match_id: the first entry that matches
pub fn usb_match_id<'a>(
    ids: &'a [UsbDeviceId],
    d: &UsbDevice,
    f: &UsbInterface,
) -> Option<&'a UsbDeviceId> {
    ids.iter().find(|id| id.matches(d, f))
}

/// PRODUCT and TYPE of a device's or interface's uevent (Linux usb_uevent)
pub fn product_env(d: &UsbDevice, env: &mut Vec<Vec<u8>>) {
    env.push(
        format!(
            "PRODUCT={:x}/{:x}/{:x}",
            d.vendor_id, d.product_id, d.bcd_device
        )
        .into_bytes(),
    );
    env.push(
        format!(
            "TYPE={}/{}/{}",
            d.device_class, d.device_subclass, d.device_protocol
        )
        .into_bytes(),
    );
}

/// An interface's modalias (Linux modalias_show, usb_if_uevent)
pub fn modalias(d: &UsbDevice, f: &UsbInterface) -> String {
    format!(
        "usb:v{:04X}p{:04X}d{:04X}dc{:02X}dsc{:02X}dp{:02X}ic{:02X}isc{:02X}ip{:02X}in{:02X}",
        d.vendor_id,
        d.product_id,
        d.bcd_device,
        d.device_class,
        d.device_subclass,
        d.device_protocol,
        f.class,
        f.subclass,
        f.protocol,
        f.number
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hw::usb::UsbSpeed;

    fn dev(class: u8) -> UsbDevice {
        let mut d = UsbDevice::new(1, 1, UsbSpeed::High);
        d.vendor_id = 0x46f4;
        d.product_id = 0x0001;
        d.bcd_device = 0x0000;
        d.device_class = class;
        d
    }

    fn intf(cl: u8, sc: u8, pr: u8) -> UsbInterface {
        UsbInterface {
            num_endpoints: 2,
            class: cl,
            subclass: sc,
            protocol: pr,
            ..Default::default()
        }
    }

    const STORAGE: [UsbDeviceId; 1] = [UsbDeviceId::interface_info(8, 6, 0x50)];

    #[test]
    fn interface_info() {
        assert!(usb_match_id(&STORAGE, &dev(0), &intf(8, 6, 0x50)).is_some());
        assert!(usb_match_id(&STORAGE, &dev(0), &intf(8, 6, 0)).is_none());
        assert!(usb_match_id(&STORAGE, &dev(0), &intf(8, 2, 0x50)).is_none());
        // a vendor-specific device's interfaces need the vendor matched
        assert!(usb_match_id(&STORAGE, &dev(0xff), &intf(8, 6, 0x50)).is_none());
    }

    #[test]
    fn device_ids() {
        let id = UsbDeviceId::device(0x0403, 0x6001);
        let mut d = dev(0);
        assert!(!id.matches(&d, &intf(0xff, 0xff, 0xff)));
        d.vendor_id = 0x0403;
        d.product_id = 0x6001;
        assert!(id.matches(&d, &intf(0xff, 0xff, 0xff)));
        // vendor given: a vendor-specific device's interfaces match
        let mut both = id;
        both.match_flags |= id_match::INT_CLASS;
        both.b_interface_class = 0xff;
        d.device_class = 0xff;
        assert!(both.matches(&d, &intf(0xff, 0, 0)));
        let range = UsbDeviceId {
            match_flags: id_match::DEV_LO | id_match::DEV_HI,
            bcd_device_lo: 0x0100,
            bcd_device_hi: 0x0200,
            ..UsbDeviceId::NONE
        };
        d.bcd_device = 0x0400;
        assert!(!range.matches(&d, &intf(0, 0, 0)));
        d.bcd_device = 0x0200;
        assert!(range.matches(&d, &intf(0, 0, 0)));
    }

    #[test]
    fn modalias_format() {
        let mut d = dev(0);
        d.vendor_id = 0x0403;
        d.product_id = 0x6001;
        d.bcd_device = 0x0400;
        assert_eq!(
            modalias(&d, &intf(0xff, 0xff, 0xff)),
            "usb:v0403p6001d0400dc00dsc00dp00icFFiscFFipFFin00"
        );
        let mut env = Vec::new();
        product_env(&d, &mut env);
        assert_eq!(env[0], b"PRODUCT=403/6001/400");
        assert_eq!(env[1], b"TYPE=0/0/0");
    }
}
