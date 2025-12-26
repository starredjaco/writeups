# Switchboard

## TL;DR
- kUAF and double-free in ``kmalloc-cg-32`` without ``CONFIG_SLAB_FREELIST_HARDENED``

## Challenge Description

> Your standard SLAB notetaking app!

- Category: **pwn**

## Exploitation
### Analyzing the source code

- For this challenge we are provided with the source code [switchboard.c](assets/switchboard.c) that implements a switchboard kernel module, with different device management operations. It uses the `switch_device` struct:

```c
struct switch_device {
    char *buf;
    void *head, *tail, *seek;
    int len;
    uint8_t inuse;
    uint8_t freed;
    unsigned long t_settings;
};
```

    * ``obj_new``: Creates a new switch_device object, allocates a 32-byte buffer, initializes all pointers to the buffer start, sets ``inuse=1``, and adds it to the global list.
    * ``obj_select``: Selects a device by index from the device list.
    * ``rx_handle``: `copy_from_user` handler. If the device ``inuse==0``, it allocates a new 32-byte buffer first.
    * ``tx_handle``: `copy_to_user` handler. Uses `dev->t_settings` for retransmission.
    * ``buf_reset``: Sets seek=head and marks device as not in use (inuse=0). If already not in use, frees the buffer memory.
    * ``n_set``: Sets the maximum data length for the selected device's buffer, stored in ``dev->len``.
    * ``settings``: Configures transmission settings for the selected device. The t_settings field uses bit 0 to control retransmission behavior in tx_handle.

### Getting the flag

![flag](assets/flag.gif)

### Solvers

You can find the solver [here](assets/main.c).