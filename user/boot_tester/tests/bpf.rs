//! BPF syscall tests
//!
//! Tests:
//! - Test BPF hash map creation
//! - Test BPF array map creation
//! - Test hash map insert/lookup/delete
//! - Test array map update/lookup
//! - Test map iteration with get_next_key
//! - Test BPF program load
//! - Test invalid map type
//! - Test invalid fd

use super::helpers::{print, println, print_num};
use core::mem::size_of;
use hk_syscall::{
    sys_bpf, sys_close,
    BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM,
    BPF_MAP_DELETE_ELEM, BPF_MAP_GET_NEXT_KEY, BPF_PROG_LOAD,
    BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_ARRAY, BPF_PROG_TYPE_SOCKET_FILTER,
    BPF_ANY,
};

/// Map creation attribute structure
#[repr(C)]
struct MapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
}

/// Map element operation attribute structure
#[repr(C)]
struct MapElemAttr {
    map_fd: u32,
    _pad0: u32,
    key: u64,
    value: u64,
    flags: u64,
}

/// Program load attribute structure
#[repr(C)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

/// BPF instruction structure
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

impl BpfInsn {
    const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: (src << 4) | (dst & 0x0f),
            off,
            imm,
        }
    }
}

// BPF opcodes
const BPF_ALU64: u8 = 0x07;
const BPF_JMP: u8 = 0x05;
const BPF_MOV: u8 = 0xb0;
const BPF_EXIT: u8 = 0x90;
const BPF_K: u8 = 0x00;

/// Run all BPF tests
pub fn run_tests() {
    test_hash_map_create();
    test_array_map_create();
    test_hash_map_ops();
    test_array_map_ops();
    test_map_iteration();
    test_prog_load();
    test_invalid_map_type();
    test_invalid_fd();
}

/// Test BPF hash map creation
fn test_hash_map_create() {
    let attr = MapCreateAttr {
        map_type: BPF_MAP_TYPE_HASH,
        key_size: 4,
        value_size: 8,
        max_entries: 10,
        map_flags: 0,
        inner_map_fd: 0,
        numa_node: 0,
        map_name: [0; 16],
    };

    let fd = sys_bpf(
        BPF_MAP_CREATE,
        &attr as *const _ as u64,
        size_of::<MapCreateAttr>() as u32,
    );

    if fd < 0 {
        print(b"BPF_HASH_CREATE:FAIL: returned ");
        print_num(fd);
        return;
    }

    let close_ret = sys_close(fd as u64);
    if close_ret != 0 {
        print(b"BPF_HASH_CREATE:FAIL: close returned ");
        print_num(close_ret);
        return;
    }

    println(b"BPF_HASH_CREATE:OK");
}

/// Test BPF array map creation
fn test_array_map_create() {
    let attr = MapCreateAttr {
        map_type: BPF_MAP_TYPE_ARRAY,
        key_size: 4, // Array maps require key_size = 4
        value_size: 8,
        max_entries: 10,
        map_flags: 0,
        inner_map_fd: 0,
        numa_node: 0,
        map_name: [0; 16],
    };

    let fd = sys_bpf(
        BPF_MAP_CREATE,
        &attr as *const _ as u64,
        size_of::<MapCreateAttr>() as u32,
    );

    if fd < 0 {
        print(b"BPF_ARRAY_CREATE:FAIL: returned ");
        print_num(fd);
        return;
    }

    let close_ret = sys_close(fd as u64);
    if close_ret != 0 {
        print(b"BPF_ARRAY_CREATE:FAIL: close returned ");
        print_num(close_ret);
        return;
    }

    println(b"BPF_ARRAY_CREATE:OK");
}

/// Test hash map insert/lookup/delete operations
fn test_hash_map_ops() {
    // Create hash map
    let create_attr = MapCreateAttr {
        map_type: BPF_MAP_TYPE_HASH,
        key_size: 4,
        value_size: 8,
        max_entries: 10,
        map_flags: 0,
        inner_map_fd: 0,
        numa_node: 0,
        map_name: [0; 16],
    };

    let map_fd = sys_bpf(
        BPF_MAP_CREATE,
        &create_attr as *const _ as u64,
        size_of::<MapCreateAttr>() as u32,
    );

    if map_fd < 0 {
        print(b"BPF_HASH_OPS:FAIL: create returned ");
        print_num(map_fd);
        return;
    }

    // Insert element: key=42, value=0xDEADBEEF
    let key: u32 = 42;
    let value: u64 = 0xDEADBEEF;
    let update_attr = MapElemAttr {
        map_fd: map_fd as u32,
        _pad0: 0,
        key: &key as *const _ as u64,
        value: &value as *const _ as u64,
        flags: BPF_ANY,
    };

    let ret = sys_bpf(
        BPF_MAP_UPDATE_ELEM,
        &update_attr as *const _ as u64,
        size_of::<MapElemAttr>() as u32,
    );

    if ret != 0 {
        print(b"BPF_HASH_OPS:FAIL: insert returned ");
        print_num(ret);
        sys_close(map_fd as u64);
        return;
    }

    // Lookup element
    let mut read_value: u64 = 0;
    let lookup_attr = MapElemAttr {
        map_fd: map_fd as u32,
        _pad0: 0,
        key: &key as *const _ as u64,
        value: &mut read_value as *mut _ as u64,
        flags: 0,
    };

    let ret = sys_bpf(
        BPF_MAP_LOOKUP_ELEM,
        &lookup_attr as *const _ as u64,
        size_of::<MapElemAttr>() as u32,
    );

    if ret != 0 {
        print(b"BPF_HASH_OPS:FAIL: lookup returned ");
        print_num(ret);
        sys_close(map_fd as u64);
        return;
    }

    if read_value != 0xDEADBEEF {
        print(b"BPF_HASH_OPS:FAIL: expected 0xDEADBEEF, got ");
        print_num(read_value as i64);
        sys_close(map_fd as u64);
        return;
    }

    // Delete element
    let delete_attr = MapElemAttr {
        map_fd: map_fd as u32,
        _pad0: 0,
        key: &key as *const _ as u64,
        value: 0,
        flags: 0,
    };

    let ret = sys_bpf(
        BPF_MAP_DELETE_ELEM,
        &delete_attr as *const _ as u64,
        size_of::<MapElemAttr>() as u32,
    );

    if ret != 0 {
        print(b"BPF_HASH_OPS:FAIL: delete returned ");
        print_num(ret);
        sys_close(map_fd as u64);
        return;
    }

    // Lookup should now fail with ENOENT (-2)
    let ret = sys_bpf(
        BPF_MAP_LOOKUP_ELEM,
        &lookup_attr as *const _ as u64,
        size_of::<MapElemAttr>() as u32,
    );

    if ret != -2 {
        print(b"BPF_HASH_OPS:FAIL: lookup after delete returned ");
        print_num(ret);
        sys_close(map_fd as u64);
        return;
    }

    sys_close(map_fd as u64);
    println(b"BPF_HASH_OPS:OK");
}

/// Test array map update/lookup operations
fn test_array_map_ops() {
    // Create array map
    let create_attr = MapCreateAttr {
        map_type: BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: 8,
        max_entries: 10,
        map_flags: 0,
        inner_map_fd: 0,
        numa_node: 0,
        map_name: [0; 16],
    };

    let map_fd = sys_bpf(
        BPF_MAP_CREATE,
        &create_attr as *const _ as u64,
        size_of::<MapCreateAttr>() as u32,
    );

    if map_fd < 0 {
        print(b"BPF_ARRAY_OPS:FAIL: create returned ");
        print_num(map_fd);
        return;
    }

    // Update index 5
    let key: u32 = 5;
    let value: u64 = 0xCAFEBABE;
    let update_attr = MapElemAttr {
        map_fd: map_fd as u32,
        _pad0: 0,
        key: &key as *const _ as u64,
        value: &value as *const _ as u64,
        flags: BPF_ANY,
    };

    let ret = sys_bpf(
        BPF_MAP_UPDATE_ELEM,
        &update_attr as *const _ as u64,
        size_of::<MapElemAttr>() as u32,
    );

    if ret != 0 {
        print(b"BPF_ARRAY_OPS:FAIL: update returned ");
        print_num(ret);
        sys_close(map_fd as u64);
        return;
    }

    // Lookup index 5
    let mut read_value: u64 = 0;
    let lookup_attr = MapElemAttr {
        map_fd: map_fd as u32,
        _pad0: 0,
        key: &key as *const _ as u64,
        value: &mut read_value as *mut _ as u64,
        flags: 0,
    };

    let ret = sys_bpf(
        BPF_MAP_LOOKUP_ELEM,
        &lookup_attr as *const _ as u64,
        size_of::<MapElemAttr>() as u32,
    );

    if ret != 0 {
        print(b"BPF_ARRAY_OPS:FAIL: lookup returned ");
        print_num(ret);
        sys_close(map_fd as u64);
        return;
    }

    if read_value != 0xCAFEBABE {
        print(b"BPF_ARRAY_OPS:FAIL: expected 0xCAFEBABE, got ");
        print_num(read_value as i64);
        sys_close(map_fd as u64);
        return;
    }

    // Test out of bounds (index 20 > max_entries 10)
    let bad_key: u32 = 20;
    let bad_lookup_attr = MapElemAttr {
        map_fd: map_fd as u32,
        _pad0: 0,
        key: &bad_key as *const _ as u64,
        value: &mut read_value as *mut _ as u64,
        flags: 0,
    };

    let ret = sys_bpf(
        BPF_MAP_LOOKUP_ELEM,
        &bad_lookup_attr as *const _ as u64,
        size_of::<MapElemAttr>() as u32,
    );

    if ret != -2 {
        // ENOENT
        print(b"BPF_ARRAY_OPS:FAIL: out of bounds lookup returned ");
        print_num(ret);
        sys_close(map_fd as u64);
        return;
    }

    sys_close(map_fd as u64);
    println(b"BPF_ARRAY_OPS:OK");
}

/// Test map iteration with get_next_key
fn test_map_iteration() {
    // Create hash map
    let create_attr = MapCreateAttr {
        map_type: BPF_MAP_TYPE_HASH,
        key_size: 4,
        value_size: 4,
        max_entries: 10,
        map_flags: 0,
        inner_map_fd: 0,
        numa_node: 0,
        map_name: [0; 16],
    };

    let map_fd = sys_bpf(
        BPF_MAP_CREATE,
        &create_attr as *const _ as u64,
        size_of::<MapCreateAttr>() as u32,
    );

    if map_fd < 0 {
        print(b"BPF_ITERATE:FAIL: create returned ");
        print_num(map_fd);
        return;
    }

    // Insert 3 elements
    for i in 1u32..=3 {
        let key = i;
        let value = i * 10;
        let update_attr = MapElemAttr {
            map_fd: map_fd as u32,
            _pad0: 0,
            key: &key as *const _ as u64,
            value: &value as *const _ as u64,
            flags: BPF_ANY,
        };

        let ret = sys_bpf(
            BPF_MAP_UPDATE_ELEM,
            &update_attr as *const _ as u64,
            size_of::<MapElemAttr>() as u32,
        );

        if ret != 0 {
            print(b"BPF_ITERATE:FAIL: insert returned ");
            print_num(ret);
            sys_close(map_fd as u64);
            return;
        }
    }

    // Get first key (key=NULL)
    let mut next_key: u32 = 0;
    let next_attr = MapElemAttr {
        map_fd: map_fd as u32,
        _pad0: 0,
        key: 0, // NULL for first key
        value: &mut next_key as *mut _ as u64,
        flags: 0,
    };

    let ret = sys_bpf(
        BPF_MAP_GET_NEXT_KEY,
        &next_attr as *const _ as u64,
        size_of::<MapElemAttr>() as u32,
    );

    if ret != 0 {
        print(b"BPF_ITERATE:FAIL: get_next_key(NULL) returned ");
        print_num(ret);
        sys_close(map_fd as u64);
        return;
    }

    // Count iterations
    let mut count = 1;
    let mut current_key = next_key;

    loop {
        let next_attr = MapElemAttr {
            map_fd: map_fd as u32,
            _pad0: 0,
            key: &current_key as *const _ as u64,
            value: &mut next_key as *mut _ as u64,
            flags: 0,
        };

        let ret = sys_bpf(
            BPF_MAP_GET_NEXT_KEY,
            &next_attr as *const _ as u64,
            size_of::<MapElemAttr>() as u32,
        );

        if ret == -2 {
            // ENOENT - end of iteration
            break;
        }

        if ret != 0 {
            print(b"BPF_ITERATE:FAIL: get_next_key returned ");
            print_num(ret);
            sys_close(map_fd as u64);
            return;
        }

        count += 1;
        current_key = next_key;

        if count > 10 {
            println(b"BPF_ITERATE:FAIL: infinite loop");
            sys_close(map_fd as u64);
            return;
        }
    }

    if count != 3 {
        print(b"BPF_ITERATE:FAIL: expected 3 keys, got ");
        print_num(count);
        sys_close(map_fd as u64);
        return;
    }

    sys_close(map_fd as u64);
    println(b"BPF_ITERATE:OK");
}

/// Test BPF program load
fn test_prog_load() {
    // Simple program: mov r0, 0; exit
    // This returns 0 from the BPF program
    let insns = [
        BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0), // mov r0, 0
        BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),          // exit
    ];

    let license = b"GPL\0";

    let attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_SOCKET_FILTER,
        insn_cnt: 2,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 0,
        log_size: 0,
        log_buf: 0,
        kern_version: 0,
        prog_flags: 0,
        prog_name: [0; 16],
        prog_ifindex: 0,
        expected_attach_type: 0,
    };

    let fd = sys_bpf(
        BPF_PROG_LOAD,
        &attr as *const _ as u64,
        size_of::<ProgLoadAttr>() as u32,
    );

    if fd < 0 {
        print(b"BPF_PROG_LOAD:FAIL: returned ");
        print_num(fd);
        return;
    }

    let close_ret = sys_close(fd as u64);
    if close_ret != 0 {
        print(b"BPF_PROG_LOAD:FAIL: close returned ");
        print_num(close_ret);
        return;
    }

    println(b"BPF_PROG_LOAD:OK");
}

/// Test invalid map type returns error
fn test_invalid_map_type() {
    let attr = MapCreateAttr {
        map_type: 999, // Invalid
        key_size: 4,
        value_size: 8,
        max_entries: 10,
        map_flags: 0,
        inner_map_fd: 0,
        numa_node: 0,
        map_name: [0; 16],
    };

    let fd = sys_bpf(
        BPF_MAP_CREATE,
        &attr as *const _ as u64,
        size_of::<MapCreateAttr>() as u32,
    );

    if fd >= 0 {
        println(b"BPF_INVALID_TYPE:FAIL: should have returned error");
        sys_close(fd as u64);
        return;
    }

    if fd != -22 {
        // EINVAL
        print(b"BPF_INVALID_TYPE:FAIL: expected -22, got ");
        print_num(fd);
        return;
    }

    println(b"BPF_INVALID_TYPE:OK");
}

/// Test operations on invalid fd
fn test_invalid_fd() {
    let key: u32 = 1;
    let mut value: u64 = 0;
    let lookup_attr = MapElemAttr {
        map_fd: 9999, // Invalid fd
        _pad0: 0,
        key: &key as *const _ as u64,
        value: &mut value as *mut _ as u64,
        flags: 0,
    };

    let ret = sys_bpf(
        BPF_MAP_LOOKUP_ELEM,
        &lookup_attr as *const _ as u64,
        size_of::<MapElemAttr>() as u32,
    );

    if ret >= 0 {
        println(b"BPF_INVALID_FD:FAIL: should have returned error");
        return;
    }

    if ret != -9 {
        // EBADF
        print(b"BPF_INVALID_FD:FAIL: expected -9, got ");
        print_num(ret);
        return;
    }

    println(b"BPF_INVALID_FD:OK");
}
