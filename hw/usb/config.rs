//! Descriptor parsing (Linux drivers/usb/core/config.c): the device
//! descriptor, and a configuration descriptor with its interfaces,
//! endpoints and SuperSpeed endpoint companions.

use alloc::vec::Vec;

use super::{EndpointType, UsbConfig, UsbDevice, UsbEndpoint, UsbInterface, descriptor_type};

/// Device descriptor length
pub const USB_DT_DEVICE_SIZE: usize = 18;
/// Configuration descriptor length (without what follows it)
pub const USB_DT_CONFIG_SIZE: usize = 9;

fn le16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

/// Fill `dev` from its device descriptor; false if `b` is not one
pub fn parse_device(dev: &mut UsbDevice, b: &[u8]) -> bool {
    if b.len() < USB_DT_DEVICE_SIZE || b[1] != descriptor_type::DEVICE {
        return false;
    }
    dev.bcd_usb = le16(b, 2);
    dev.device_class = b[4];
    dev.device_subclass = b[5];
    dev.device_protocol = b[6];
    dev.max_packet_size0 = b[7];
    dev.vendor_id = le16(b, 8);
    dev.product_id = le16(b, 10);
    dev.bcd_device = le16(b, 12);
    dev.num_configurations = b[17];
    true
}

/// wTotalLength of a configuration descriptor's first 9 bytes
pub fn config_total_length(b: &[u8]) -> Option<u16> {
    if b.len() < USB_DT_CONFIG_SIZE || b[1] != descriptor_type::CONFIGURATION {
        return None;
    }
    Some(le16(b, 2))
}

/// A configuration and its interface settings (Linux
/// usb_parse_configuration): descriptors other than interface,
/// endpoint and companion are skipped, a truncated one ends the parse
pub fn parse_config(b: &[u8]) -> Option<(UsbConfig, Vec<UsbInterface>)> {
    config_total_length(b)?;
    let cfg = UsbConfig {
        value: b[5],
        num_interfaces: b[4],
        attributes: b[7],
        max_power: b[8],
    };
    let mut intfs: Vec<UsbInterface> = Vec::new();
    // The last endpoint was skipped: its companion goes too
    let mut skipped = false;
    let mut i = b[0] as usize;
    while i + 2 <= b.len() {
        let len = b[i] as usize;
        if len < 2 || i + len > b.len() {
            break;
        }
        let d = &b[i..i + len];
        match d[1] {
            descriptor_type::INTERFACE if len >= 9 => intfs.push(UsbInterface {
                number: d[2],
                alternate_setting: d[3],
                num_endpoints: d[4],
                class: d[5],
                subclass: d[6],
                protocol: d[7],
                endpoints: Vec::new(),
            }),
            descriptor_type::ENDPOINT if len >= 7 => {
                // Linux usb_parse_endpoint: endpoint 0, a number past 15
                // or one the setting already has is skipped
                let num = d[2] & !0x80;
                if let Some(intf) = intfs.last_mut()
                    && num != 0
                    && num < 16
                    && !intf.endpoints.iter().any(|e| e.address == d[2])
                {
                    skipped = false;
                    intf.endpoints.push(UsbEndpoint {
                        address: d[2],
                        ep_type: EndpointType::from_attributes(d[3]),
                        max_packet_size: le16(d, 4),
                        interval: d[6],
                        max_burst: 0,
                        bytes_per_interval: 0,
                    });
                } else {
                    skipped = true;
                }
            }
            descriptor_type::SS_ENDPOINT_COMP if len >= 6 && !skipped => {
                if let Some(ep) = intfs.last_mut().and_then(|f| f.endpoints.last_mut()) {
                    ep.max_burst = d[2].min(15);
                    ep.bytes_per_interval = le16(d, 4);
                }
            }
            _ => {}
        }
        i += len;
    }
    Some((cfg, intfs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hw::usb::UsbSpeed;

    /// QEMU's usb-storage at SuperSpeed: one BOT interface, two bulk
    /// endpoints with companions
    const STORAGE_SS: [u8; 44] = [
        9, 2, 44, 0, 1, 1, 0, 0xc0, 0, // config
        9, 4, 0, 0, 2, 8, 6, 0x50, 0, // interface
        7, 5, 0x81, 2, 0, 4, 0, // bulk in, 1024
        6, 0x30, 15, 0, 0, 0, // companion
        7, 5, 0x02, 2, 0, 4, 0, // bulk out
        6, 0x30, 15, 0, 0, 0,
    ];

    #[test]
    fn config_storage() {
        let (cfg, intfs) = parse_config(&STORAGE_SS).unwrap();
        assert_eq!(cfg.value, 1);
        assert_eq!(cfg.num_interfaces, 1);
        assert_eq!(cfg.attributes, 0xc0);
        assert_eq!(intfs.len(), 1);
        let f = &intfs[0];
        assert_eq!((f.class, f.subclass, f.protocol), (8, 6, 0x50));
        assert_eq!(f.endpoints.len(), 2);
        assert_eq!(f.endpoints[0].maxp(), 1024);
        assert_eq!(f.endpoints[0].max_burst, 15);
        assert_eq!(f.bulk_eps(), Some((0x81, 0x02)));
    }

    #[test]
    fn config_bad_endpoints_skipped() {
        let mut b = STORAGE_SS;
        // endpoint 0, then a duplicate of 0x81: both dropped
        b[20] = 0x80;
        b[33] = 0x80;
        let (_, intfs) = parse_config(&b).unwrap();
        assert!(intfs[0].endpoints.is_empty());
        let mut d = STORAGE_SS;
        d[33] = 0x81;
        let (_, intfs) = parse_config(&d).unwrap();
        assert_eq!(intfs[0].endpoints.len(), 1);
        let mut r = STORAGE_SS;
        r[20] = 0x91; // number 17
        assert_eq!(parse_config(&r).unwrap().1[0].endpoints.len(), 1);
    }

    #[test]
    fn config_truncated() {
        // the second endpoint cut short: dropped, the rest kept
        let (_, intfs) = parse_config(&STORAGE_SS[..36]).unwrap();
        assert_eq!(intfs[0].endpoints.len(), 1);
        assert!(parse_config(&STORAGE_SS[..8]).is_none());
        let mut bad = STORAGE_SS;
        bad[1] = 1;
        assert!(parse_config(&bad).is_none());
        // a zero-length descriptor stops the walk
        let mut z = STORAGE_SS;
        z[9] = 0;
        assert!(parse_config(&z).unwrap().1.is_empty());
    }

    #[test]
    fn device_desc() {
        // QEMU usb-serial (FTDI FT232)
        let d = [
            18, 1, 0x00, 0x02, 0, 0, 0, 8, 0x03, 0x04, 0x01, 0x60, 0x00, 0x04, 1, 2, 3, 1,
        ];
        let mut dev = UsbDevice::new(1, 5, UsbSpeed::Full);
        assert!(parse_device(&mut dev, &d));
        assert_eq!((dev.vendor_id, dev.product_id), (0x0403, 0x6001));
        assert_eq!((dev.bcd_usb, dev.bcd_device), (0x0200, 0x0400));
        assert_eq!((dev.max_packet_size0, dev.num_configurations), (8, 1));
        assert!(!parse_device(&mut dev, &d[..17]));
    }
}
