# kerbab

## TL;DR
Craft a malicious .so  to exploit an off-by-null vuln into off-by-one in SLUB to overwrite ``current->thread_info.flags`` to disable SECCOMP and read the flag.

## Challenge Description
This challenge was part of HackOn 2024 CTF
- Category: **pwn**

## Exploitation
### Analyzing the source code
We are given a list of files common in kernel exploitation challenges

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
