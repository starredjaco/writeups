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

The most relevant files are initramfs.cpio.gz, which holds the filesystem of the VM we are going to spawn to exploit the vulnerable kernel module. The `vmlinuz-4.19.306` is the kernel image of the VM. We can see how it is spawned in the `run.sh` file:

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

