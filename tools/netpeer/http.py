#!/usr/bin/env python3
"""One-shot HTTP/1.0 responder for the test network (tools/qemu-net.sh).

slirp's guestfwd runs this once per TCP connection to 10.0.2.100:80 with
the connection on stdin/stdout: read the request head, answer GET/HEAD
with a fixed body, then exit (closing the connection).
"""
import sys

BODY = b"hk netpeer ok\n"


def read_head(f):
    """Request line and headers, up to the blank line (bounded)"""
    lines = []
    for _ in range(100):
        line = f.readline(8192)
        if not line or line in (b"\r\n", b"\n"):
            break
        lines.append(line)
    return lines


def main():
    head = read_head(sys.stdin.buffer)
    method = head[0].split(b" ", 1)[0] if head else b""
    if method in (b"GET", b"HEAD"):
        status, body = b"200 OK", BODY
    else:
        status, body = b"501 Not Implemented", b""
    out = sys.stdout.buffer
    out.write(b"HTTP/1.0 " + status + b"\r\n")
    out.write(b"Content-Type: text/plain\r\n")
    out.write(b"Content-Length: %d\r\n" % len(body))
    out.write(b"Connection: close\r\n\r\n")
    if method != b"HEAD":
        out.write(body)
    out.flush()


if __name__ == "__main__":
    main()
