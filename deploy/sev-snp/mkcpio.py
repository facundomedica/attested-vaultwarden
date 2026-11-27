#!/usr/bin/env python3
"""Write a directory tree as a `newc` cpio archive to stdout, deterministically.

    mkcpio.py <root> <mtime>

Entries are sorted by path; every entry is owned by 0:0, carries <mtime>,
device numbers 0, and inode numbers counted from 1; directories have nlink
2 and everything else nlink 1. Only directories, regular files and symbolic
links are accepted. The output therefore depends on file names, contents,
permission bits and link targets, and on nothing the build host's file
system adds.
"""
import os
import stat
import sys


def header(ino, mode, nlink, mtime, size, name):
    name = name.encode() + b"\0"
    fields = [ino, mode, 0, 0, nlink, mtime, size, 0, 0, 0, 0, len(name), 0]
    h = b"070701" + b"".join(b"%08X" % f for f in fields) + name
    return h + b"\0" * (-len(h) % 4)


def main():
    root, mtime = sys.argv[1], int(sys.argv[2])
    out = sys.stdout.buffer
    paths = []
    for d, dirs, files in os.walk(root):
        for n in dirs + files:
            paths.append(os.path.relpath(os.path.join(d, n), root))
    ino = 0
    for rel in sorted(paths):
        full = os.path.join(root, rel)
        st = os.lstat(full)
        ino += 1
        perm = stat.S_IMODE(st.st_mode)
        if stat.S_ISDIR(st.st_mode):
            out.write(header(ino, stat.S_IFDIR | perm, 2, mtime, 0, rel))
        elif stat.S_ISLNK(st.st_mode):
            target = os.readlink(full).encode()
            out.write(header(ino, stat.S_IFLNK | 0o777, 1, mtime, len(target), rel))
            out.write(target + b"\0" * (-len(target) % 4))
        elif stat.S_ISREG(st.st_mode):
            data = open(full, "rb").read()
            out.write(header(ino, stat.S_IFREG | perm, 1, mtime, len(data), rel))
            out.write(data + b"\0" * (-len(data) % 4))
        else:
            raise SystemExit(f"{rel}: not a directory, regular file or symlink")
    out.write(header(0, 0, 1, 0, 0, "TRAILER!!!"))


main()
