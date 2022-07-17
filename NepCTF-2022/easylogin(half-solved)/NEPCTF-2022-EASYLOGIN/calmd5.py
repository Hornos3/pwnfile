from hashlib import md5
from pwn import *

def get_md5_digint(bytes):
    return int(md5(bytes).hexdigest(), 16)

for i in range(1000000):
    message = p32(i*1000) * 8
    hexdig = get_md5_digint(message)
    if hexdig & ((1 << 8) - 1) == 0 and hexdig & ((1 << 128) - (1 << 120)) == 0:
        print(message)
        print(hexdig)

# 54052103791711052204349287341804800