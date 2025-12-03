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
    * `gift()`: sets global variable `jury_gift` to the address of `stdout` (libc leak), and kills the current thread (this is really important).
    * `bonus_entry()`: checks if function's first parameter is equal to a hardcoded value `rdi = 0x1337c0de`. If it evaluates to true, sets global variable `bonus_enabled` to 1.
- The 4th option in the menu (Show results) `results_entry`: prints the flag if `bonus_enabled == 1` -> win function! Looks like an easy ret2win challenge.

- The other menu options:
    * `submit_story()`: Asks for a size and sets global variable `g_story_len` to its value and then checks if it is within the valid bounds `size < 129`, if it is valid, calls `read()` with `g_story_len` and stores it in a 136 byte buffer. Copies our buffer to global variable `last_story` and prints the number of bytes read.
    * `last_story()`: prints `last_story` content.
    * `show_jury_info()`: prints `g_story_len` and `jury_gift` if `bonus_enabled != 0`.
    * `show_public_results()`: calls `results_entry` if `bonus_enabled != 0`. **<- win func**

- The vulnerability is in the size check:

```c
void submit_story(int fd){
    ...
    send_line(param_1,"=== Submit a new story ===");
    send_line(param_1,"The jury needs a short moment to prepare the evaluation...");
    send_str(param_1,"Choose a length limit for your story: ");
    size = recv_int(param_1);
    ...
    else {
    g_story_len = size;
    if (size < 129) {
        send_line(fd,"[*] The jury is thinking (0.5s)...");
        usleep(500000); // !!!!
        send_line(fd,"Now type your story:");
        int nb = read(fd,buf,g_story_len);
    ...
}

```

- Global variables are shared between connections, so there is a clear race condition (toctou) vulnerability. If we create 2 connections, we can send a valid length and modify `g_story_len` to a high number with another concurrent connection while we are at the ``usleep``. This could be done too without the sleep, but this way it takes less tries.

1. Connection 1 sends length 1 (to pass the check and access the read function), enters `usleep`
2. Connection 2 sends length 300, it does not pass the check but sets `g_story_len = 300`
3. Connection 1 enters ``read(fd, buffer, 300)``

- There is no canary and no PIE, so we can rop anywhere we want inside the binary. We just need to calculate the offset and overflow the buffer just like any ret2win challenge.

- After a lot of tries to ROP into `results_entry` to print the flag bypassing the checks, it would always crash the thread because of the tampered rbp, so I decided I would use the intended path: `gift`, to leak libc and kill the thread preventing crash of the instance -> toctou again -> use `pop_rdi` to set `rdi = 1` and call `bonus_entry` to set `bonus_enabled = 1` -> call gift to kill the thread again to prevent a crash. The `gift` function was really helpful to make this work, because the remote instance would always crash when trying to return to a valid address after tampering the stack.

- Now we just have to use any connection to choose option 4 and print the flag. 

### Getting the flag
- The script takes more than one try to work, but always ends up printing the flag (crashing the instance too)

![flag](assets/flag.gif)