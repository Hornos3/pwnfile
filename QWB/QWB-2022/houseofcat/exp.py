from pwn import *
context.log_level='debug'
context.arch='amd64'

io = process('./house_of_cat')

gdb.attach(io)
time.sleep(5)
io.sendlineafter(b'mew mew mew~~~~~~\n', "CAT | QWB QWXF");

io.interactive()
