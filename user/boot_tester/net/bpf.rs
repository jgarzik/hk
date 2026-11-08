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
//! - BPF_HASH_BUDGET: a hash map whose full size cannot be had is ENOMEM
//!   at create (Linux preallocates its elements)
//! - BPF_MAP_INFO: BPF_OBJ_GET_INFO_BY_FD fills struct bpf_map_info,
//!   writes the length it used back to attr.info.info_len, takes a
//!   larger buffer whose extra bytes are zero, and is E2BIG when they
//!   are not (bpf_check_uarg_tail_zero)

use crate::harness::{fail_num, pass};
use crate::helpers::{print, print_num, println};
use core::mem::size_of;
use hk_syscall::{
    BPF_ANY, BPF_MAP_CREATE, BPF_MAP_DELETE_ELEM, BPF_MAP_GET_NEXT_KEY, BPF_MAP_LOOKUP_ELEM,
    BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH, BPF_MAP_UPDATE_ELEM, BPF_PROG_LOAD,
    BPF_PROG_TYPE_SOCKET_FILTER, sys_bpf, sys_close,
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
    test_prog_load_big();
    test_invalid_map_type();
    test_invalid_fd();
    test_hash_budget();
    test_map_info();
}

fn hash_attr(key_size: u32, value_size: u32, max_entries: u32) -> MapCreateAttr {
    MapCreateAttr {
        map_type: BPF_MAP_TYPE_HASH,
        key_size,
        value_size,
        max_entries,
        map_flags: 0,
        inner_map_fd: 0,
        numa_node: 0,
        map_name: [0; 16],
    }
}

fn map_create(attr: &MapCreateAttr) -> i64 {
    sys_bpf(
        BPF_MAP_CREATE,
        attr as *const _ as u64,
        size_of::<MapCreateAttr>() as u32,
    )
}

fn test_hash_budget() {
    const ENOMEM: i64 = -12;
    // 2^20 elements of 64 KB: 64 GB
    let fd = map_create(&hash_attr(256, 65536, 1 << 20));
    if fd >= 0 {
        sys_close(fd as u64);
    }
    crate::harness::verdict(b"BPF_HASH_BUDGET", fd == ENOMEM, fd);
}

/// union bpf_attr's info member
#[repr(C)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

/// BPF_OBJ_GET_INFO_BY_FD of `fd` into `buf` claiming `len` bytes:
/// (result, info_len written back)
fn get_info(fd: i64, buf: &mut [u8], len: u32) -> (i64, u32) {
    use hk_syscall::BPF_OBJ_GET_INFO_BY_FD;
    let mut a = InfoAttr {
        bpf_fd: fd as u32,
        info_len: len,
        info: buf.as_mut_ptr() as u64,
    };
    let r = sys_bpf(
        BPF_OBJ_GET_INFO_BY_FD,
        &mut a as *mut _ as u64,
        size_of::<InfoAttr>() as u32,
    );
    (r, a.info_len)
}

fn test_map_info() {
    const E2BIG: i64 = -7;
    let mut t = crate::harness::T::new(b"BPF_MAP_INFO");
    let fd = map_create(&hash_attr(4, 8, 10));
    let u32_at = |b: &[u8], o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    let mut buf = [0u8; 256];
    let (r, len) = get_info(fd, &mut buf, 24);
    t.eq(b"short", r, 0);
    t.eq(b"short len", i64::from(len), 24);
    let fields = [
        u32_at(&buf, 0),
        u32_at(&buf, 8),
        u32_at(&buf, 12),
        u32_at(&buf, 16),
    ];
    t.ok(
        b"fields",
        fields == [BPF_MAP_TYPE_HASH, 4, 8, 10],
        i64::from(fields[0]),
    );
    let mut buf = [0u8; 256];
    let (r, len) = get_info(fd, &mut buf, 256);
    t.eq(b"long", r, 0);
    // struct bpf_map_info: 88 bytes (Linux 6.8), 104 with the map hash
    t.ok(b"long len", len == 88 || len == 104, i64::from(len));
    let mut buf = [0u8; 256];
    buf[200] = 1;
    t.eq(b"tail", get_info(fd, &mut buf, 256).0, E2BIG);
    sys_close(fd as u64);
    t.done();
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

    pass(b"BPF_HASH_CREATE");
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

    pass(b"BPF_ARRAY_CREATE");
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
    pass(b"BPF_HASH_OPS");
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
    pass(b"BPF_ARRAY_OPS");
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
    pass(b"BPF_ITERATE");
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

    pass(b"BPF_PROG_LOAD");
}

/// A 600,000-instruction program (4.8 MB) loads with CAP_BPF, as Linux
/// allows up to BPF_COMPLEXITY_LIMIT_INSNS: the kernel's copy of it
/// needs a heap block far past the slab's largest (vmalloc)
fn test_prog_load_big() {
    const N: usize = 600_000;
    let len = (N * 8) as u64;
    let p = hk_syscall::sys_mmap(0, len, 3, 0x22, -1, 0); // RW, PRIVATE|ANON
    if p < 0 {
        println(b"BPF_PROG_LOAD_BIG:FAIL mmap");
        return;
    }
    // SAFETY: the mapping just made, N u64s
    let insns = unsafe { core::slice::from_raw_parts_mut(p as *mut u64, N) };
    insns.fill(0xb7); // r0 = 0
    insns[N - 1] = 0x95; // exit
    let license = b"GPL\0";
    let attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_SOCKET_FILTER,
        insn_cnt: N as u32,
        insns: p as u64,
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
    hk_syscall::sys_munmap(p as u64, len);
    if fd < 0 {
        fail_num(b"BPF_PROG_LOAD_BIG:FAIL returned ", fd);
        return;
    }
    sys_close(fd as u64);
    pass(b"BPF_PROG_LOAD_BIG");
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

    pass(b"BPF_INVALID_TYPE");
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

    pass(b"BPF_INVALID_FD");
}
