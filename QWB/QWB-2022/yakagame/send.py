from pwn import *

io = remote('123.56.87.28', 18640)

with open('./base64.txt', 'r') as f:
	c = f.read()
	print(c)

io.sendlineafter(b'give me your code(attack or exp base64code)\n', c.encode())
io.interactive()