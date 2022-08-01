#!/bin/sh

qemu-system-x86_64  \
-m 512M \
-cpu kvm64,+smep,+smap \
-smp 4 \
-kernel ./vmlinux \
-append "console=ttyS0 nokaslr quiet" \
-initrd rootfs.img \
-monitor /dev/null \
-nographic

