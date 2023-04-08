import base64
from pwn import *
import re
context.log_level = 'debug'

class Interactor:
    def __init__(self, remote_addr='', port=-1, privilege_root=False):
        self.remote_addr: str = remote_addr
        self.port: int = port
        self.io = remote(remote_addr, port)
        self.privilege_root = privilege_root
        self.__LS_SEPARATOR_REGEX = re.compile(b"\x1b\\[[0-9;]*m")

        if not privilege_root:
            first_output = self.io.recvuntil(b"$ ")
            self.symbol = b'$'
        else:
            first_output = self.io.recvuntil(b"# ")
        last_line = first_output.split(b"\n")[-1]
        self.current_path = last_line.split(b" ")[0]

    def __del__(self):
        self.io.close()

    def wait_for_input(self, path=''):
        return self.io.recvuntil(self.current_path + b" " + self.symbol + b" ")

    def get_output(self):
        return self.io.recvuntil(self.current_path + b" " + self.symbol + b" ", drop=True)

    def ls(self):
        self.io.sendline(b"ls")
        self.io.recvline()
        output = self.get_output()
        print(output)
        file_list = re.split(self.__LS_SEPARATOR_REGEX, output)
        for f in file_list:
            if f == '' or re.match(b"\\s*", f):
                file_list.remove(f)
        return [f.decode() for f in file_list]

    def get_ascii_file(self, path: str, out: str):
        log.info("Ready to cat " + path + " ...")
        context.log_level = 'info'
        self.io.sendline(b"cat " + path.encode())
        self.io.recvline()
        output = self.get_output()
        output.replace(b"\r", b"")
        with open(out, "w") as output_file:
            output_file.write(output.decode())
        context.log_level = 'debug'
        log.info("Ascii file " + path + " saved to " + out + ".")

    def get_binary_file(self, path: str, out: str):
        log.info("Ready to dump " + path + " ...")
        context.log_level = 'info'
        self.io.sendline(b"base64 " + path.encode())
        self.io.recvline()
        output = self.get_output().decode()
        lines = output.split("\r\n")
        for one_line in lines:      # exclude other output
            if not re.match("[0-9A-Za-z+/=]+", one_line):
                lines.remove(one_line)
        for i in range(len(lines)):
            if lines[i].endswith("="):
                lines = lines[:i+1]
        output = ''.join(lines)
        with open("temp.b64", "w") as b64file:
            b64file.write('\n'.join(lines))
        print(len(output))
        binary_content = base64.b64decode(output)
        with open(out, "wb") as output_file:
            output_file.write(binary_content)
        context.log_level = 'debug'
        log.info("Binary file " + path + " saved to " + out + ".")