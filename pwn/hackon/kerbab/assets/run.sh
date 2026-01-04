#! /bin/bash

        set -e

        gcc exploit.c -shared -fPIC -o libxpl.so
        mv libxpl.so initramfs/home/user/
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




