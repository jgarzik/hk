//! `#!` interpreter scripts (Linux fs/binfmt_script.c)
//!
//! The first line of a script, within the first [`BINPRM_BUF_SIZE`]
//! bytes, names its interpreter and at most one argument (the rest of the
//! line, spaces and all). exec then runs the interpreter with argv
//! `[interpreter, argument?, script path, original argv[1..]]`; an
//! interpreter may be a script too, up to [`MAX_DEPTH`] levels.

/// Bytes of a file exec reads to recognize its format (Linux
/// BINPRM_BUF_SIZE)
pub const BINPRM_BUF_SIZE: usize = 256;

/// Most interpreter rewrites of one exec (Linux exec_binprm: depth > 5
/// is ELOOP)
pub const MAX_DEPTH: usize = 5;

const ENOEXEC: i32 = 8;

fn spacetab(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// An interpreter path and its optional argument
pub type Interp<'a> = (&'a [u8], Option<&'a [u8]>);

fn terminator(c: u8) -> bool {
    spacetab(c) || c == 0
}

/// The interpreter and its optional argument of the file starting with
/// `head` (at most BINPRM_BUF_SIZE bytes): None if it is not a script,
/// Err(ENOEXEC) for a script whose first line names no interpreter, or
/// whose interpreter path may be cut off by the buffer's end (Linux
/// load_script)
pub fn parse(head: &[u8]) -> Option<Result<Interp<'_>, i32>> {
    let head = &head[..head.len().min(BINPRM_BUF_SIZE)];
    if !head.starts_with(b"#!") {
        return None;
    }
    Some(parse_line(head))
}

fn parse_line(head: &[u8]) -> Result<Interp<'_>, i32> {
    let mut end = match head.iter().position(|&c| c == b'\n') {
        Some(nl) => nl,
        None => {
            // No newline in the buffer: the interpreter path must end
            // before the buffer does (a space, tab or NUL after it)
            let start = (2..head.len())
                .find(|&i| !spacetab(head[i]))
                .ok_or(ENOEXEC)?;
            if !head[start..].iter().any(|&c| terminator(c)) {
                return Err(ENOEXEC);
            }
            head.len()
        }
    };
    while end > 2 && spacetab(head[end - 1]) {
        end -= 1;
    }
    let line = &head[..end];
    let name_start = (2..line.len())
        .find(|&i| !spacetab(line[i]))
        .ok_or(ENOEXEC)?;
    let name_end = (name_start..line.len())
        .find(|&i| terminator(line[i]))
        .unwrap_or(line.len());
    let name = &line[name_start..name_end];
    let arg = if name_end < line.len() && line[name_end] != 0 {
        (name_end..line.len())
            .find(|&i| !spacetab(line[i]))
            .map(|s| {
                let a = &line[s..];
                // The argument stops at a NUL
                &a[..a.iter().position(|&c| c == 0).unwrap_or(a.len())]
            })
    } else {
        None
    };
    Ok((name, arg))
}

/// argv for the interpreter (Linux load_script: remove_arg_zero, then
/// the script's path, the argument and the interpreter in front)
pub fn rewrite_argv(
    argv: &[alloc::vec::Vec<u8>],
    interp: &[u8],
    arg: Option<&[u8]>,
    script: &[u8],
) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    let mut out = alloc::vec::Vec::with_capacity(argv.len() + 2);
    out.push(interp.to_vec());
    if let Some(a) = arg {
        out.push(a.to_vec());
    }
    out.push(script.to_vec());
    out.extend(argv.iter().skip(1).cloned());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(h: &[u8]) -> Interp<'_> {
        parse(h).unwrap().unwrap()
    }

    #[test]
    fn plain_and_arg() {
        assert_eq!(parse(b"\x7fELF"), None);
        assert_eq!(ok(b"#!/bin/sh\necho"), (&b"/bin/sh"[..], None));
        assert_eq!(ok(b"#! /bin/sh -e\n"), (&b"/bin/sh"[..], Some(&b"-e"[..])));
        // The argument is the rest of the line, inner spaces kept,
        // trailing ones dropped
        assert_eq!(
            ok(b"#!/usr/bin/env  python3 -u  \t\nx"),
            (&b"/usr/bin/env"[..], Some(&b"python3 -u"[..]))
        );
        assert_eq!(ok(b"#!/bin/sh\t\n"), (&b"/bin/sh"[..], None));
    }

    #[test]
    fn bad_lines() {
        assert_eq!(parse(b"#!\n"), Some(Err(ENOEXEC)));
        assert_eq!(parse(b"#!   \t\n"), Some(Err(ENOEXEC)));
        // No newline and no end of the path within the buffer
        let mut long = alloc::vec![b'#', b'!'];
        long.extend(core::iter::repeat_n(b'a', 300));
        assert_eq!(parse(&long), Some(Err(ENOEXEC)));
        // No newline but the path ends: the line runs to the buffer end
        let mut cut = alloc::vec::Vec::from(&b"#!/bin/sh "[..]);
        cut.extend(core::iter::repeat_n(b'x', 300));
        let (n, a) = ok(&cut);
        assert_eq!(n, b"/bin/sh");
        assert_eq!(a.unwrap().len(), BINPRM_BUF_SIZE - 10);
    }

    #[test]
    fn argv() {
        let orig = [b"./s".to_vec(), b"one".to_vec()];
        let v = rewrite_argv(&orig, b"/bin/sh", Some(b"-e"), b"/tmp/s");
        assert_eq!(
            v,
            [
                b"/bin/sh".to_vec(),
                b"-e".to_vec(),
                b"/tmp/s".to_vec(),
                b"one".to_vec()
            ]
        );
    }
}
