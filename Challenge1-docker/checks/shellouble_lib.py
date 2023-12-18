from pwn import *
from checklib import *

context.log_level = 'CRITICAL'
# context.log_level = 'debug'

PORT = 56789
DEFAULT_RECV_SIZE = 4096
TCP_CONNECTION_TIMEOUT = 5
TCP_OPERATIONS_TIMEOUT = 7

class CheckMachine:

    def __init__(self, checker: BaseChecker):
        self.c = checker
        self.port = PORT

    def connection(self) -> remote:
        io = remote(self.c.host, self.port, timeout=TCP_CONNECTION_TIMEOUT)
        io.settimeout(TCP_OPERATIONS_TIMEOUT)
        return io

    def exit_(self, io: remote) -> None:
        io.sendlineafter(b'> ', b'0')

    def register(self, io: remote, username: str, password: str, description: str, status: Status) -> None:
        io.sendlineafter(b'> ', b'1')
        io.sendlineafter(b': ', username.encode())
        io.sendlineafter(b': ', password.encode())
        io.sendlineafter(b': ', description.encode())
        resp = io.recvline()[:-1]
        self.c.assert_eq(resp, b'Success!', 'Invalid response on register', status)

    def login(self, io: remote, username: str, password: str, status: Status) -> None:
        io.sendlineafter(b'> ', b'2')
        io.sendlineafter(b': ', username.encode())
        io.sendlineafter(b': ', password.encode())
        resp = io.recvline()[:-1]
        self.c.assert_eq(resp, b'Login successful.', 'Invalid response on login', status)
  
    def show_info(self, io: remote)-> bytes:
        #login first
        io.sendlineafter(b'> ', b'3')
        io.recvline()
        io.recvline()
        io.recvuntil(b': ')
        resp2 = io.recvline()[:-1]
        # print(b"Flag: "+resp2)
        return resp2

    def shellcode(self, io: remote, status: Status) -> None:
        #login first
        io.sendline(b'1')
        shellcode =b'1\xc0H\xba\x88wfUD3"\x11H\x87\xfe\xc9\xc3'
        io.recvuntil(b"> Shellcode()\n> ")
        io.sendline(shellcode)
        resp = io.recv(0x3b)
        # print(b"Received from shellcode: "+resp)
        self.c.assert_eq(resp, b"\nChoose one:\n1. Shellcode\n2. Number\n3. Show Info\n0. Exit\n> ", 'Invalid response on Shellcode', status)
        
    def number(self, io: remote, status: Status) -> None:
        #login first
        def send_double(int_value):
            double_value = struct.unpack('d', (bytes.fromhex(format(int_value, '016x')))[::-1])[0]
            # print(double_value)
            io.sendlineafter(b"> ",(str(double_value)).encode())
        
        def show(idx):
            io.sendlineafter(b'> ', b'1')
            io.sendlineafter(b'> ', str(idx).encode())   
        
        def fix():
            io.sendlineafter(b'> ', b'2')
            io.sendlineafter(b'> ', b'30')
            send_double(0x555555555555)
            # io.sendlineafter(b'> ', b'4.63557053855665e-310')
            send_double(0xffffffffffff)
            # io.sendlineafter(b'> ', b'1.390671161566996e-309')
            for i in range(28):
                io.sendlineafter(b'> ', str(i).encode())
            
        def delete(idx):
            io.sendlineafter(b'> ', b'3')
            io.sendlineafter(b'> ', str(idx).encode())
        
        io.sendlineafter(b'> ', b'2')
        io.sendlineafter(b'> ', b'2')
        send_double(0xffffffffffff)
        # io.sendlineafter(b'> ', b'1.390671161566996e-309')
        send_double(0x555555555555)
        # io.sendlineafter(b'> ', b'4.63557053855665e-310')
        
        # show
        show(0)
        resp = io.recvline()[:-1]
        self.c.assert_eq(resp, b'0x0.0ffffffffp-1022', 'Invalid response on send-show number', status)
        show(1)
        resp = io.recvline()[:-1]
        self.c.assert_eq(resp, b'0x0.0555555555555p-1022', 'Invalid response on send-show number', status)
        
        # fix
        fix()
        # check fix (show)
        show(0)
        resp = io.recvline()[:-1]
        self.c.assert_eq(resp, b'0x0.0555555555555p-1022', 'Invalid response on fix number', status)
        show(1)
        resp = io.recvline()[:-1]
        self.c.assert_eq(resp, b'0x0.0ffffffffffffp-1022', 'Invalid response on fix number', status)
        show(3)
        resp = io.recvline()[:-1]
        self.c.assert_eq(resp, b'0x1p+0', 'Invalid response on fix number', status)
        
        # delete
        delete(0)
        delete(1)
        # check delete (show)
        show(0)
        resp = io.recvline()[:-1]
        self.c.assert_eq(resp, b'0x0p+0', 'Invalid response on delete number', status)
        show(1)
        resp = io.recvline()[:-1]
        self.c.assert_eq(resp, b'0x0p+0', 'Invalid response on delete number', status)

        # return banner shellcode() - number() - show_info()
        io.sendlineafter(b'> ', b'0')
        