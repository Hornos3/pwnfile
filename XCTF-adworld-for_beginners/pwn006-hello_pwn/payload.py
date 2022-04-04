from pwn import *

io = remote('111.200.241.244', 61049)
io.send(b'89abaaun')
io.interactive()