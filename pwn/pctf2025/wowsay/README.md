# Magic Scrolls - HTB Heap Challenge


## TL;DR

- The only thing we are given is the challenge description, and a remote server to connect to.
- Format string your way into finding out ``win()`` function and GOT table addresses, and overwrite one of the entries to print the flag.

## Challenge Description

> Cowsay is so out... Old & boring. Which is why I made wowsay!

Category: **pwn**

## Enumeration
### Trial and error

- When we connect to the remote challenge we only see a fancy banner and a prompt asking for input. As soon as we send something they print it back to us, so the first thing we try is format string. There is a limit of 100 bytes so we can create big payloads. 
- We can leak some qwords from the stack with a loop:

```python
for i in range(30):
        io = remote("18.212.136.134", 1337)
        payload = f'%{i}$p'.encode()
        payload = payload.ljust(0x10, b'\x00')
        io.send(payload)
```

[stack](assets/leak%20main%20addr.gif)

- We can see at position 23 that there is no PIE in the challenge, so I compiled a binary locally to see the address of the GOT entries.
