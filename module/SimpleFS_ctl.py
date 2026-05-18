#!/usr/bin/env python3

import argparse
import ctypes
import fcntl
import os
import signal
import sys

SIMPLEFS_SECTOR_SIZE = 512
SIMPLEFS_HASH_SIZE = 32
SIMPLEFS_NAME_BUF = 64
SIMPLEFS_NAME_PREFIX = "file_"

_IOC_NRBITS = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_DIRBITS = 2

_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS

_IOC_NONE = 0
_IOC_WRITE = 1
_IOC_READ = 2

def _IOC(direction: int, magic: str, nr: int, size: int) -> int:
    return ((direction << _IOC_DIRSHIFT) |
            (size << _IOC_SIZESHIFT) |
            (ord(magic) << _IOC_TYPESHIFT) |
            (nr << _IOC_NRSHIFT))

def _IO(magic: str, nr: int) -> int:
    return _IOC(_IOC_NONE, magic, nr, 0)

def _IOWR(magic: str, nr: int, size: int) -> int:
    return _IOC(_IOC_READ | _IOC_WRITE, magic, nr, size)

class SimpleFSFileHash(ctypes.Structure):
    _fields_ = [
        ("file_index", ctypes.c_uint32),
        ("name", ctypes.c_char * SIMPLEFS_NAME_BUF),
        ("hash", ctypes.c_uint8 * SIMPLEFS_HASH_SIZE),
    ]

class SimpleFSHashList(ctypes.Structure):
    _fields_ = [
        ("capacity", ctypes.c_uint32),
        ("count", ctypes.c_uint32),
        ("copied", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("hashes_ptr", ctypes.c_uint64),
    ]

class SimpleFSSectorMap(ctypes.Structure):
    _fields_ = [
        ("file_index", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("name", ctypes.c_char * SIMPLEFS_NAME_BUF),
        ("first_sector", ctypes.c_uint64),
        ("num_sectors", ctypes.c_uint64),
    ]

assert ctypes.sizeof(SimpleFSFileHash) == 100, "SimpleFSFileHash size mismatch"
assert ctypes.sizeof(SimpleFSHashList) == 24, "SimpleFSHashList size mismatch"
assert ctypes.sizeof(SimpleFSSectorMap) == 88, "SimpleFSSectorMap size mismatch"

SIMPLEFS_IOC_MAGIC = 'S'
SIMPLEFS_IOC_ZERO_ALL = _IO(SIMPLEFS_IOC_MAGIC, 1)
SIMPLEFS_IOC_ERASE = _IO(SIMPLEFS_IOC_MAGIC, 2)
SIMPLEFS_IOC_GET_HASHES = _IOWR(SIMPLEFS_IOC_MAGIC, 3, ctypes.sizeof(SimpleFSHashList))
SIMPLEFS_IOC_GET_MAP = _IOWR(SIMPLEFS_IOC_MAGIC, 4, ctypes.sizeof(SimpleFSSectorMap))

def open_mount(path: str) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY)

def list_simplefs_files(mnt: str) -> list:
    names = [n for n in os.listdir(mnt) if n.startswith(SIMPLEFS_NAME_PREFIX)]
    def idx(n):

        try:
            return int(n[len(SIMPLEFS_NAME_PREFIX):])
        except ValueError:
            return -1
        
    names.sort(key=idx)
    return names

def cmd_zero(mnt: str) -> int:
    fd = open_mount(mnt)

    try:
        fcntl.ioctl(fd, SIMPLEFS_IOC_ZERO_ALL)
    finally:
        os.close(fd)

    print("OK: all files zeroed")
    return 0

def cmd_erase(mnt: str) -> int:
    fd = open_mount(mnt)

    try:
        fcntl.ioctl(fd, SIMPLEFS_IOC_ERASE)
    finally:
        os.close(fd)
        
    print("OK: superblocks and files erased. Unmount and remount to reformat.")
    return 0

def cmd_hashes(mnt: str) -> int:
    fd = open_mount(mnt)
    try:
        hl = SimpleFSHashList(capacity = 0, count = 0, copied = 0, _pad = 0, hashes_ptr = 0)
        fcntl.ioctl(fd, SIMPLEFS_IOC_GET_HASHES, hl, True)

        if hl.count == 0:
            print("(no files)")
            return 0

        ArrType = SimpleFSFileHash * hl.count
        arr = ArrType()
        hl.capacity = hl.count
        hl.hashes_ptr = ctypes.addressof(arr)
        fcntl.ioctl(fd, SIMPLEFS_IOC_GET_HASHES, hl, True)

        print(f"Total files: {hl.count}, hashes received: {hl.copied}")

        for i in range(hl.copied):
            entry = arr[i]
            name = entry.name.decode("utf-8", errors="replace")
            h = bytes(entry.hash).hex()
            print(f"[{entry.file_index:4d}] {name:<20s} sha256={h}")

    finally:
        os.close(fd)
    return 0

def cmd_map(mnt: str, name: str) -> int:
    fd = open_mount(mnt)
    try:
        m = SimpleFSSectorMap()
        m.file_index = 0xFFFFFFFF
        encoded = name.encode("utf-8")

        if len(encoded) >= SIMPLEFS_NAME_BUF:
            print(f"Filename too long (max {SIMPLEFS_NAME_BUF - 1})", file = sys.stderr)
            return 1
        
        m.name = encoded

        fcntl.ioctl(fd, SIMPLEFS_IOC_GET_MAP, m, True)

        print(f"File '{m.name.decode()}' (index={m.file_index})")
        print(f"first sector: {m.first_sector}")
        bytes_total = m.num_sectors * SIMPLEFS_SECTOR_SIZE
        print(f"length: {m.num_sectors} sectors ({bytes_total} bytes)")

    finally:
        os.close(fd)

    return 0

def cmd_info(mnt: str) -> int:
    names = list_simplefs_files(mnt)
    print(f"Mount point: {mnt}")
    print(f"Files: {len(names)}")

    for name in names[:10]:
        path = os.path.join(mnt, name)
        try:
            st = os.stat(path)
            print(f"{name} : {st.st_size} bytes")

        except OSError as e:
            print(f"{name} : <stat: {e}>", file=sys.stderr)

    if len(names) > 10:
        print(f"... {len(names) - 10} more")

    return 0

def cmd_test(mnt: str) -> int:
    names = list_simplefs_files(mnt)

    if not names:
        print("No files to test.")
        return 0

    ok = 0
    bad = 0
    print(f"Running test over {len(names)} files...")

    for name in names:
        path = os.path.join(mnt, name)
        out_bytes = os.urandom(8)
        out_val = int.from_bytes(out_bytes, "little")

        try:
            fd = os.open(path, os.O_RDWR)

        except OSError as e:
            print(f"open {path}: {e}", file=sys.stderr)
            bad += 1
            continue

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            n = os.write(fd, out_bytes)

            if n != 8:
                print(f"write {path}: wrote {n} instead of 8", file=sys.stderr)
                bad += 1
                continue
            os.fsync(fd)

            os.lseek(fd, 0, os.SEEK_SET)
            in_bytes = os.read(fd, 8)

            if len(in_bytes) != 8:
                print(f"read {path}: read {len(in_bytes)} instead of 8", file=sys.stderr)
                bad += 1
                continue
            in_val = int.from_bytes(in_bytes, "little")

            if in_val == out_val:
                ok += 1
            else:
                print(f"MISMATCH {name}: written {out_val:016x}, read {in_val:016x}", file=sys.stderr)
                bad += 1

        except OSError as e:
            print(f"I/O {path}: {e}", file=sys.stderr)
            bad += 1

        finally:
            os.close(fd)

    print(f"Result: OK={ok}, BAD={bad} of {ok + bad}")
    return 1 if bad else 0

def main() -> int:
    parser = argparse.ArgumentParser(
        prog = "SimpleFS_ctl",
        description = "SimpleFS userspace tool (Python)",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="cmd", metavar="COMMAND")
    sub.required = True

    p = sub.add_parser("test", help="random write->read sanity check")
    p.add_argument("mount")
    p = sub.add_parser("zero", help="ioctl: zero out all files")
    p.add_argument("mount")
    p = sub.add_parser("erase", help="ioctl: erase entire FS")
    p.add_argument("mount")
    p = sub.add_parser("hashes", help="ioctl: SHA-256 of every file")
    p.add_argument("mount")
    p = sub.add_parser("map", help="ioctl: sector mapping for a file")
    p.add_argument("mount")
    p.add_argument("filename")
    p = sub.add_parser("info", help="readdir + stat (no ioctl)")
    p.add_argument("mount")

    args = parser.parse_args()

    handlers = {
        "test": lambda: cmd_test(args.mount),
        "zero": lambda: cmd_zero(args.mount),
        "erase": lambda: cmd_erase(args.mount),
        "hashes": lambda: cmd_hashes(args.mount),
        "map": lambda: cmd_map(args.mount, args.filename),
        "info": lambda: cmd_info(args.mount),
    }
    return handlers[args.cmd]()


if __name__ == "__main__":
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    try:
        sys.exit(main() or 0)

    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)

    except OSError as e:
        print(f"SimpleFS_ctl: {e}", file=sys.stderr)
        sys.exit(1)

    except KeyboardInterrupt:
        sys.exit(130)