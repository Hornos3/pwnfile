# MINI-LCTF 2022 - kgadget

>  Copyright © 2022 arttnba3@L-team

## Introduction

Welcome to MINI-LCTF 2022! 

It seems that `one_gadget` in glibc is of great power in pwning on user land, usually you'd just hijack the RIP to it and there'll be a shell for you.

But what about the kernel land? Every time we try to pwn the kernel, `commit_creds(prepare_kernel_cred(NULL))` is always needed, which should always be constructed within a ROP chain.

THAT'S TOO CUMBERSOME!!!

So here's the task for you, my baby pwner: **can you help me find out an `one_gadget` on kernel land?**

Here are some kernel compile options you may need : )

```
CONFIG_STATIC_USERMODEHELPER=y
CONFIG_STATIC_USERMODEHELPER_PATH=""
```

## How to start?

> This paragraph is for pwner who just enter the world of kernel exploit. If you're experienced enough, just ignore it  ; )

As you can see, this challenge is located in Linux kernel, which is unlike those pwning in user land you had done before. This one gives you the whole operating environment of a Linux kernel, and you're expected to exploit the vulnerability as an unprivileged local user, and gain the root privilege in the end. The flag is set to be readable by root only, which is the checkpoint of a successful exploit.

Unlike existed release version (e.g. Ubuntu) of Linux, only the kernel itself (aka `bzImage`) and a simple file system (aka `rootfs.cpio`) will be provided, and the whole environment will be run by `QEMU`. So if there's no `QEMU` on your computer, install it by:

```shell
$ sudo apt-get install -y qemu qemu-system-x86
```

Now you can simply run the challenge by:

```shell
$ ./run.sh
```

Configurations to start the kernel are set in `run.sh`, including what we mainly focus: the protection it turns on (e.g. `smep` or `kaslr`). 

You can get more information about kernel exploit on CTF-wiki or other websites.(e.g. [my blog](https://arttnba3.cn/2021/02/21/NOTE-0X02-LINUX-KERNEL-PWN-PART-I/))
