# story contest - toctou 

## TL;DR

- Abuse a Race Condition vulnerability to bypass a size check and craft a rop chain to get the flag.

## Challenge Description

> It’s time for you to tell your best story, and maybe you’ll be rewarded accordingly. Good luck !

Category: **pwn**

## Exploitation
### Analyzing the source code

- The first thing we do is check the security mechanisms enabled in the challenge:

```console
lokete@kpwn:~/Desktop/ctf/heroctf/storycontest$ pwn checksec storycontest 
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

- We see there is no stack protector and no PIE (there is also Partial RELRO, but it is not relevant for this challenge). Decompiling the binary we see it is creating a listener, and prints a menu with several options to every concurrent connection.

```console

=== StoryJury ===
1) Submit a story
2) Show last story
3) Show jury info
4) Show results
5) Quit
> 

``` 

- There are a couple of interesting functions that are not listed in this menu:
    * `gift()`: sets global variable `jury_gift` to the address of `stdout` (libc leak).
    * `bonus_entry()`: checks if function's first parameter is equal to a hardcoded value `rdi = 0x1337c0de`. If it evaluates to true, sets global variable `bonus_enabled` to 1.
- The 4th option in the menu (Show results) `results_entry`: prints the flag if `bonus_enabled == 1` -> win function! Looks like an easy ret2win challenge.

- The other menu options:
    * 
