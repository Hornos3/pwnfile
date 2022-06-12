from pwn import *
from LibcSearcher import *
context.log_level='debug'

ld_path = "/root/Desktop/pwnfile/ld/ld-2.27.so"
libc_path = "/root/Desktop/pwnfile/CISCN/2021/lonely_wolf/libc-2.27.so"
p = process([ld_path, "./lonelywolf"], env={"LD_PRELOAD":libc_path})

io = process('./lonelywolf')

io.interactive()