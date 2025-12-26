# Switchboard

## TL;DR
- kUAF and double-free in ``kmalloc-cg-32`` without ``CONFIG_SLAB_FREELIST_HARDENED``

## Challenge Description

> Your standard SLAB notetaking app!

- Category: **pwn**

## Exploitation
### Analyzing the source code